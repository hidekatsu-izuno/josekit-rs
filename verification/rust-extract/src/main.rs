use quote::ToTokens;
use std::{env, fs, path::Path};
use syn::{
    parse::Parse,
    visit::{self, Visit},
    Block, Expr, ImplItem, ImplItemFn, Item, Stmt,
};

type Check<T> = Result<T, String>;

fn parsed_tokens<T: Parse + ToTokens>(code: &str) -> Check<String> {
    let parsed: T = syn::parse_str(code).map_err(|e| format!("{e}: {code}"))?;
    Ok(parsed.to_token_stream().to_string())
}

fn require<T: Parse + ToTokens>(actual: &T, supported: &str, context: &str) -> Check<()> {
    if actual.to_token_stream().to_string() == parsed_tokens::<T>(supported)? {
        Ok(())
    } else {
        Err(format!(
            "{context}: unsupported Rust: {}",
            actual.to_token_stream()
        ))
    }
}

fn method<'a>(file: &'a syn::File, ty: &str, name: &str) -> Check<&'a ImplItemFn> {
    let mut methods = file
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Impl(item)
                if item.attrs.is_empty()
                    && item.trait_.is_none()
                    && item.self_ty.to_token_stream().to_string() == ty =>
            {
                Some(item)
            }
            _ => None,
        })
        .flat_map(|item| item.items.iter())
        .filter_map(|item| match item {
            ImplItem::Fn(function) if function.sig.ident == name => Some(function),
            _ => None,
        });
    match (methods.next(), methods.next()) {
        (Some(function), None) if function.attrs.iter().all(|a| a.path().is_ident("doc")) => {
            Ok(function)
        }
        _ => Err(format!(
            "{ty}::{name}: expected one unconditional Rust method"
        )),
    }
}

fn rust_file(root: &Path, path: &str) -> Check<syn::File> {
    let path = root.join(path);
    let source = fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    syn::parse_file(&source).map_err(|e| format!("{}: {e}", path.display()))
}

fn free_function<'a>(file: &'a syn::File, name: &str) -> Check<&'a syn::ItemFn> {
    file.items
        .iter()
        .find_map(|item| match item {
            Item::Fn(function) if function.sig.ident == name && function.attrs.is_empty() => {
                Some(function)
            }
            _ => None,
        })
        .ok_or_else(|| format!("missing Rust function {name}"))
}

fn statement_tokens(code: &str) -> Check<String> {
    let block: Block =
        syn::parse_str(&format!("{{ {code} }}")).map_err(|e| format!("{e}: {code}"))?;
    match block.stmts.as_slice() {
        [statement] => Ok(statement.to_token_stream().to_string()),
        _ => Err(format!(
            "translation rule must contain one Rust statement: {code}"
        )),
    }
}

fn translate(statements: &[Stmt], rules: &[(&str, &str)], context: &str) -> Check<String> {
    statements
        .iter()
        .map(|statement| {
            let parsed = statement.to_token_stream().to_string();
            for (source, lean) in rules {
                if parsed == statement_tokens(source)? {
                    return Ok(*lean);
                }
            }
            Err(format!("{context}: no translation rule for {parsed}"))
        })
        .collect::<Check<Vec<_>>>()
        .map(|lines| lines.join("\n"))
}

fn check_prefix(block: &Block, prefix: &str, context: &str) -> Check<usize> {
    let expected: Block = syn::parse_str(&format!("{{{prefix}}}"))
        .map_err(|e| format!("{context}: invalid rule: {e}"))?;
    if block.stmts.len() < expected.stmts.len() {
        return Err(format!("{context}: missing framing statements"));
    }
    let count = expected.stmts.len();
    for (actual, expected) in block.stmts.iter().zip(expected.stmts) {
        require(actual, &expected.to_token_stream().to_string(), context)?;
    }
    Ok(count)
}

fn jwk(file: &syn::File) -> Check<()> {
    let new = method(file, "JwkSet", "new")?;
    require(&new.sig, "fn new() -> Self", "JwkSet::new signature")?;
    require(
        &new.block,
        r#"{
        Self {
            keys: Vec::new(),
            params: {
                let mut map = Map::new();
                map.insert("keys".to_string(), Value::Array(Vec::new()));
                map
            },
            kid_map: BTreeMap::new(),
        }
    }"#,
        "JwkSet::new",
    )?;
    println!("def jwkNew : State := ⟨[], fun _ => []⟩\n");

    let get = method(file, "JwkSet", "get")?;
    require(
        &get.sig,
        "fn get(&self, key_id: &str) -> Vec<&Jwk>",
        "JwkSet::get signature",
    )?;
    require(
        &get.block,
        r#"{
        match self.kid_map.get(key_id) {
            Some(keys) => keys.iter().map(Arc::as_ref).collect(),
            None => Vec::new(),
        }
    }"#,
        "JwkSet::get",
    )?;
    println!("def jwkGet (state : State) (kid : String) : List Jwk :=\n  (state.buckets kid).map JwkIndex.Entry.key\n");

    let push = method(file, "JwkSet", "push_key")?;
    require(
        &push.sig,
        "fn push_key(&mut self, jwk: Jwk)",
        "JwkSet::push_key signature",
    )?;
    let rules = [
        (
            r#"match self.params.get_mut("keys") {
            Some(Value::Array(keys)) => {
                keys.push(Value::Object(jwk.as_ref().clone()));
            }
            _ => unreachable!(),
        }"#,
            "",
        ),
        ("let jwk = Arc::new(jwk);", ""),
        (
            r#"if let Some(kid) = jwk.key_id() {
            self.kid_map.entry(kid.to_string()).or_default().push(Arc::clone(&jwk));
        }"#,
            "  let state := appendToBucket state entry",
        ),
        (
            "self.keys.push(jwk);",
            "  let state := appendToEntries state entry",
        ),
    ];
    let push = translate(&push.block.stmts, &rules, "JwkSet::push_key")?;
    println!("def jwkPush (state : State) (entry : JwkIndex.Entry) : State :=\n{push}\n  state\n");

    let remove = method(file, "JwkSet", "remove_key")?;
    require(
        &remove.sig,
        "fn remove_key(&mut self, jwk: &Jwk)",
        "JwkSet::remove_key signature",
    )?;
    let [search, Stmt::Expr(Expr::If(branch), None)] = remove.block.stmts.as_slice() else {
        return Err("JwkSet::remove_key: expected search followed by a conditional update".into());
    };
    require(
        search,
        "let index = self.keys.iter().position(|e| e.as_ref() == jwk);",
        "JwkSet::remove_key search",
    )?;
    require(
        &*branch.cond,
        "let Some(index) = index",
        "JwkSet::remove_key guard",
    )?;
    if branch.else_branch.is_some() {
        return Err("JwkSet::remove_key: unsupported else branch".into());
    }
    let changes = [
        (
            r#"match self.params.get_mut("keys") {
            Some(Value::Array(keys)) => { keys.remove(index); }
            _ => unreachable!(),
        }"#,
            "",
        ),
        (
            "let removed = self.keys.remove(index);",
            "    let removed := state.entries[index]?\n    let state := eraseEntry state index",
        ),
        (
            r#"if let Some(kid) = removed.key_id() {
            if let Entry::Occupied(mut entry) = self.kid_map.entry(kid.to_string()) {
                entry.get_mut().retain(|key| !Arc::ptr_eq(key, &removed));
                if entry.get().is_empty() { entry.remove(); }
            }
        }"#,
            "    let state := retainOtherEntries state removed",
        ),
    ];
    let body = translate(
        &branch.then_branch.stmts,
        &changes,
        "JwkSet::remove_key update",
    )?;
    // Type checking prevents a translation from reading a binding before its Rust initializer.
    println!(
        r#"def jwkRemove (state : State) (key : Jwk) : State :=
  match state.entries.findIdx? (fun entry => entry.key == key) with
  | none => state
  | some index =>
{body}
    state
"#
    );
    Ok(())
}

fn closure_body<'a>(method: &'a ImplItemFn, error: &str) -> Check<&'a Block> {
    let [Stmt::Expr(Expr::MethodCall(outer), None)] = method.block.stmts.as_slice() else {
        return Err("expected one result mapping around the compact method".into());
    };
    if outer.method != "map_err" || outer.turbofish.is_some() || outer.args.len() != 1 {
        return Err("unsupported compact method error mapping".into());
    }
    let mapper = format!(
        "|err| match err.downcast::<JoseError>() {{ Ok(err) => err, Err(err) => JoseError::{error}(err), }}"
    );
    require(&outer.args[0], &mapper, "compact method error conversion")?;
    let Expr::Call(call) = &*outer.receiver else {
        return Err("expected invocation of a Rust closure".into());
    };
    let Expr::Paren(paren) = &*call.func else {
        return Err("expected closure".into());
    };
    let Expr::Closure(closure) = &*paren.expr else {
        return Err("expected closure".into());
    };
    let Expr::Block(body) = &*closure.body else {
        return Err("expected closure block".into());
    };
    if !call.args.is_empty()
        || !closure.inputs.is_empty()
        || closure.capture.is_some()
        || closure.asyncness.is_some()
        || closure.movability.is_some()
    {
        return Err("unsupported closure invocation".into());
    }
    Ok(&body.block)
}

struct TailBoundary<'a> {
    preserved: &'a [&'a str],
    violation: Option<String>,
}

impl Visit<'_> for TailBoundary<'_> {
    fn visit_pat_ident(&mut self, pattern: &syn::PatIdent) {
        if self.preserved.iter().any(|name| pattern.ident == *name) {
            self.violation = Some(format!("shadowed framing binding: {}", pattern.ident));
        }
        visit::visit_pat_ident(self, pattern);
    }

    fn visit_expr_method_call(&mut self, call: &syn::ExprMethodCall) {
        if ["verify", "decrypt", "decompress"]
            .iter()
            .any(|name| call.method == *name)
        {
            self.violation = Some(format!(
                "callback outside the translated tail: {}",
                call.method
            ));
        }
        visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_return(&mut self, _: &syn::ExprReturn) {
        self.violation = Some("explicit return before the translated tail".into());
    }

    fn visit_expr_unsafe(&mut self, _: &syn::ExprUnsafe) {
        self.violation = Some("unsafe code before the translated tail".into());
    }

    fn visit_macro(&mut self, expression: &syn::Macro) {
        if !expression.path.is_ident("bail") {
            self.violation = Some(format!(
                "unrecognized macro: {}",
                expression.path.to_token_stream()
            ));
        }
    }
}

fn suffix<'a>(
    block: &'a Block,
    prefix_len: usize,
    start: &str,
    preserved: &[&str],
    context: &str,
) -> Check<&'a [Stmt]> {
    let start = statement_tokens(start)?;
    let mut indices = block
        .stmts
        .iter()
        .enumerate()
        .filter(|(_, stmt)| stmt.to_token_stream().to_string() == start)
        .map(|(i, _)| i);
    let (Some(index), None) = (indices.next(), indices.next()) else {
        return Err(format!("{context}: expected exactly one callback boundary"));
    };
    let middle = block
        .stmts
        .get(prefix_len..index)
        .ok_or_else(|| format!("{context}: callback boundary overlaps framing"))?;
    let mut visitor = TailBoundary {
        preserved,
        violation: None,
    };
    for statement in middle {
        visitor.visit_stmt(statement);
    }
    if let Some(message) = visitor.violation {
        return Err(format!("{context}: {message}"));
    }
    Ok(&block.stmts[index..])
}

const SPLIT: &str = r#"let input = input.as_ref();
    let indexies: Vec<usize> = input.iter().enumerate().filter(|(_, b)| **b == b'.' as u8)
        .map(|(pos, _)| pos).collect();"#;

fn jws(file: &syn::File) -> Check<()> {
    let function = method(file, "JwsContext", "deserialize_compact_with_selector")?;
    let block = closure_body(function, "InvalidJwsFormat")?;
    let prefix_len = check_prefix(
        block,
        &format!(
            r#"{SPLIT}
        if indexies.len() != 2 {{
            bail!("The compact serialization form of JWS must be three parts separated by colon.");
        }}
        let header = &input[0..indexies[0]];
        let payload = &input[(indexies[0] + 1)..(indexies[1])];
        let signature = &input[(indexies[1] + 1)..];"#
        ),
        "Compact JWS framing",
    )?;

    let rules = [
        ("let message = &input[..(indexies[1])];", "  let message := CompactFlow.jwsInputBytes protectedHeader payload"),
        ("let signature = util::decode_base64_urlsafe_no_pad(signature)?;",
            "  let signature ← liftOption (decode signature)"),
        ("verifier.verify(message, &signature)?;",
            "  let _ ← event (message, signature) (if verify message signature then some () else none)"),
        (r#"let payload = if b64 { util::decode_base64_urlsafe_no_pad(payload)? }
            else { payload.to_vec() };"#,
            "  let payload ← liftOption (if encoded then decode payload else some payload)"),
        ("Ok((payload, header))", "  pure payload"),
    ];
    let body = translate(
        suffix(
            block,
            prefix_len,
            rules[0].0,
            &["input", "indexies", "payload", "signature"],
            "Compact JWS",
        )?,
        &rules,
        "Compact JWS tail",
    )?;
    println!(
        r#"def jwsTail (protectedHeader payload signature : ByteArray) (encoded : Bool)
    (decode : ByteArray → Option ByteArray) (verify : ByteArray → ByteArray → Bool) :
    Trace (ByteArray × ByteArray) ByteArray := do
{body}
"#
    );
    Ok(())
}

fn jwe(file: &syn::File) -> Check<()> {
    let function = method(file, "JweContext", "deserialize_compact_with_selector")?;
    let block = closure_body(function, "InvalidJweFormat")?;
    let prefix_len = check_prefix(
        block,
        &format!(
            r#"{SPLIT}
        if indexies.len() != 4 {{
            bail!("The compact serialization form of JWE must be five parts separated by colon.");
        }}
        let header_b64 = &input[0..indexies[0]];
        let encrypted_key_b64 = &input[(indexies[0] + 1)..(indexies[1])];
        let encrypted_key_vec;
        let encrypted_key = if encrypted_key_b64.len() > 0 {{
            encrypted_key_vec = util::decode_base64_urlsafe_no_pad(encrypted_key_b64)?;
            Some(encrypted_key_vec.as_slice())
        }} else {{ None }};
        let iv_b64 = &input[(indexies[1] + 1)..(indexies[2])];
        let iv_vec;
        let iv = if iv_b64.len() > 0 {{
            iv_vec = util::decode_base64_urlsafe_no_pad(iv_b64)?;
            Some(iv_vec.as_slice())
        }} else {{ None }};
        let ciphertext_b64 = &input[(indexies[2] + 1)..(indexies[3])];
        let ciphertext = util::decode_base64_urlsafe_no_pad(ciphertext_b64)?;
        let tag_b64 = &input[(indexies[3] + 1)..];
        let tag_vec;
        let tag = if tag_b64.len() > 0 {{
            tag_vec = util::decode_base64_urlsafe_no_pad(tag_b64)?;
            Some(tag_vec.as_slice())
        }} else {{ None }};"#
        ),
        "Compact JWE framing",
    )?;

    let rules = [
        ("let key = decrypter.decrypt(encrypted_key, cencryption, &merged)?;",
            "  let key ← event (.unwrapKey encryptedKey) (unwrap encryptedKey)"),
        (r#"if key.len() != cencryption.key_len() {
            bail!("The key size is expected to be {}: {}", cencryption.key_len(), key.len());
        }"#, "  let _ ← liftOption (if key.size != keySize then none else some ())"),
        ("let content = cencryption.decrypt(&key, iv, &ciphertext, header_b64, tag)?;",
            "  let content ← event (.authenticate key iv packet.ciphertext packet.aad tag)\n    (authenticate key iv packet.ciphertext packet.aad tag)"),
        (r#"let content = match compression {
            Some(val) => val.decompress(&content)?,
            None => content,
        };"#, "  let content ← match decompress with\n    | some f => event (.decompress content) (f content)\n    | none => pure content"),
        ("Ok((content, merged))", "  pure content"),
    ];
    let body = translate(
        suffix(
            block,
            prefix_len,
            rules[0].0,
            &["header_b64", "encrypted_key", "iv", "ciphertext", "tag"],
            "Compact JWE",
        )?,
        &rules,
        "Compact JWE tail",
    )?;
    println!(
        r#"def jweTail (header encrypted ivEncoded ciphertext tagEncoded : String) (keySize : Nat)
    (unwrap : Option ByteArray → Option ByteArray)
    (authenticate : ByteArray → Option ByteArray → ByteArray → String → Option ByteArray →
      Option ByteArray)
    (decompress : Option (ByteArray → Option ByteArray)) : Trace CompactFlow.JweCall ByteArray := do
  let packet ← liftOption (PreparedJwe.read header encrypted ivEncoded ciphertext tagEncoded)
  let encryptedKey := optionalSegment packet.encryptedKey
  let iv := optionalSegment packet.iv
  let tag := optionalSegment packet.tag
{body}
"#
    );
    Ok(())
}

fn gcm(file: &syn::File) -> Check<()> {
    let iv = free_function(file, "gcm_iv")?;
    require(
        &iv.sig,
        "fn gcm_iv(iv: Option<&[u8]>) -> anyhow::Result<&[u8; 12]>",
        "AES-GCM IV type",
    )?;
    require(
        &iv.block,
        r#"{
        iv.unwrap_or_default().try_into()
            .map_err(|_| anyhow::anyhow!("The AES-GCM IV must be 12 bytes."))
    }"#,
        "AES-GCM IV validation",
    )?;
    let decrypt = free_function(file, "decrypt_aead")?;
    check_prefix(
        &decrypt.block,
        r#"if tag.len() != 16 {
        bail!("The AES-GCM tag must be 16 bytes.");
    }
    let iv = gcm_iv(iv)?;"#,
        "AES-GCM decryption guards",
    )?;
    println!(
        r#"def gcmGuards (iv : Option ByteArray) (tag : ByteArray) : Option ByteArray := do
  if tag.size != 16 then none else
    let bytes := iv.getD ByteArray.empty
    if bytes.size = 12 then some bytes else none
"#
    );
    Ok(())
}

fn jwt(file: &syn::File) -> Check<()> {
    let guard = method(file, "JwtContext", "check_jws_header")?;
    require(
        &guard.sig,
        "fn check_jws_header(header: &JwsHeader) -> Result<(), JoseError>",
        "JWT header guard signature",
    )?;
    require(
        &guard.block,
        r#"{
        if header.critical().is_some_and(|names| names.contains(&"b64")) {
            return Err(JoseError::InvalidJwtFormat(anyhow::anyhow!(
                "JWT does not support the b64 critical header parameter."
            )));
        }
        Ok(())
    }"#,
        "JWT header guard",
    )?;
    println!("def jwtHeaderGuard (critical : Option (List String)) : Bool :=\n  !(critical.any (fun names => names.contains \"b64\"))\n");
    Ok(())
}

fn numeric_date(file: &syn::File) -> Check<()> {
    let function = free_function(file, "numeric_date")?;
    require(
        &function.sig,
        "fn numeric_date(key: &str, value: &Value) -> anyhow::Result<SystemTime>",
        "NumericDate conversion signature",
    )?;
    let rules = [
        (
            r#"let number = value.as_number()
            .ok_or_else(|| anyhow::anyhow!("The JWT {key} payload claim must be a number."))?;"#,
            "  let (wholeSeconds, floatDuration) ← number",
        ),
        (
            r#"let duration = match number.as_u64() {
            Some(seconds) => Some(Duration::from_secs(seconds)),
            None => number.as_f64().and_then(|seconds| Duration::try_from_secs_f64(seconds).ok()),
        };"#,
            "  let duration := (wholeSeconds.map (1000000000 * ·)).or floatDuration",
        ),
        (
            r#"duration.and_then(|duration| SystemTime::UNIX_EPOCH.checked_add(duration))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "The JWT {key} payload claim must be a nonnegative time representable as SystemTime: {number}"
                )
            })"#,
            "  duration >>= checkedAdd",
        ),
    ];
    let body = translate(&function.block.stmts, &rules, "NumericDate conversion")?;
    println!(
        r#"def numericDate (number : Option (Option Nat × Option Nat))
    (checkedAdd : Nat → Option α) : Option α := do
{body}
"#
    );
    Ok(())
}

fn main() -> Check<()> {
    let root = env::args_os()
        .nth(1)
        .ok_or("expected the repository root")?;
    let root = Path::new(&root);
    println!("import JosekitSpec.RustPrimitives\n\nnamespace JosekitSpec.Source\n\nopen JwkIndex (State)\nopen CompactFlow (optionalSegment)\n");
    jwk(&rust_file(root, "src/jwk/jwk_set.rs")?)?;
    jws(&rust_file(root, "src/jws/jws_context.rs")?)?;
    jwe(&rust_file(root, "src/jwe/jwe_context.rs")?)?;
    gcm(&rust_file(root, "src/jwe/enc/aesgcm.rs")?)?;
    jwt(&rust_file(root, "src/jwt/jwt_context.rs")?)?;
    numeric_date(&rust_file(root, "src/jwt/jwt_payload.rs")?)?;
    println!("end JosekitSpec.Source");
    Ok(())
}
