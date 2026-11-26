import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { WASI } from "node:wasi";

const [, , testBinary, ...args] = process.argv;
const fixtures = resolve("data");
const wasi = new WASI({
    version: "preview1",
    args: [testBinary, ...args],
    env: { RUST_TEST_THREADS: "1" },
    preopens: { [fixtures]: fixtures },
    returnOnExit: true,
});

const module = await WebAssembly.compile(await readFile(testBinary));
const instance = await WebAssembly.instantiate(module, wasi.getImportObject());
process.exitCode = wasi.start(instance);
