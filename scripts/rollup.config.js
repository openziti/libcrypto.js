import { wasm } from "@rollup/plugin-wasm";
// import { terser } from "rollup-plugin-terser";
import typescript from 'rollup-plugin-typescript2'
import babel from "rollup-plugin-babel";
// import esformatter from 'rollup-plugin-esformatter';
import { nodeResolve } from "@rollup/plugin-node-resolve";
import child_process from 'child_process';


import pkg from '../package.json'

const input = ["lib/index.js"];

const name = 'ZitiBrowzerLibCrypto';

var gitCmd = `rev-parse --short HEAD`;
var sha = child_process.execSync(`git ${gitCmd}`, {
  undefined,
  encoding: 'utf-8',
  windowsHide: true,
}).trim();

let plugins = [
  wasm({ maxFileSize: 1000000000 }),
  {
    name: "requireToGlobal",
    transform(code, id) {
      code = code.replaceAll(`GITSHA.js`, `${sha}.js`);
      return code;
    },
  },
  babel({
    exclude: "node_modules/**"
  }),
  typescript({
    typescript: require('typescript'),
    tsconfig: "tsconfig.json",
  }),
  // terser(),
];
export default [
  //
  // IIFE
  //
  {
    input,
    output: [
      {
        dir: "dist/iife",
        format: "iife",
        esModule: false,
        name: name,
        exports: "named",
      },
    ],
    external: [
      ...Object.keys(pkg.dependencies || {}),
      ...Object.keys(pkg.peerDependencies || {}),
    ],
    treeshake: true,
    plugins: plugins,
  },
  //
  // UMD
  //
  {
    input,
    output: [
      {
        dir: "dist/umd",
        format: "umd",
        esModule: false,
        name: name,
        exports: "named",
      },
    ],
    external: [
      ...Object.keys(pkg.dependencies || {}),
      ...Object.keys(pkg.peerDependencies || {}),
    ],
    treeshake: true,
    plugins: plugins,
  },
  //
  // ESM and CJS
  //
  {
    input,
    plugins: plugins.concat(
      nodeResolve(), 
      // esformatter({indent: { value: '  '}})
    ),
    output: [
      {
        dir: "dist/esm",
        format: "esm",
        exports: "named",
      },
      {
        dir: "dist/cjs",
        format: "cjs",
        exports: "named",
      },
    ],
  },
];
