import { wasm } from "@rollup/plugin-wasm";
import { terser } from "rollup-plugin-terser";
import typescript from 'rollup-plugin-typescript2'
import babel from "rollup-plugin-babel";


import pkg from '../package.json'


let plugins = [
  wasm({ maxFileSize: 1000000000 }),
  {
    name: "requireToGlobal",
    transform(code, id) {
      // let matches = code.match(/require\((['"`])([^\1\n\r]*)(\1)\)/gi);
      // if (matches) {
      //   matches.forEach((m) => {
      //     let mm = m.match(/require\((['"`])([^\1\n\r]*)(\1)\)/);
      //     code = code.replace(mm[0], `globalThis.${mm[2]}`);
      //   });
      // }
      code = code.replace("var ENVIRONMENT_IS_NODE", "ENVIRONMENT_IS_NODE");
      return code;
    },
  },
  babel({
    exclude: "node_modules/**"
  }),
  typescript({
    typescript: require('typescript'),
  }),
];
export default [
  {
    input: [
      "./src/index.js",
    ],
    output: {
      intro: "let ENVIRONMENT_IS_NODE = typeof process === 'object' && typeof process.versions === 'object' && typeof process.versions.node === 'string';",
      file: "dist/index.mjs",
      format: "esm",
    },
    // external: ["fs", "path", "crypto"],
    external: [
      ...Object.keys(pkg.dependencies || {}),
      ...Object.keys(pkg.peerDependencies || {}),
    ],
    plugins,
  },
  {
    input: [
      "./src/define.mjs",
    ],
    output: {
      intro: "let ENVIRONMENT_IS_NODE = typeof process === 'object' && typeof process.versions === 'object' && typeof process.versions.node === 'string';",
      file: "dist/define.mjs",
      format: "esm",
    },
    // external: ["fs", "path", "crypto"],
    external: [
      ...Object.keys(pkg.dependencies || {}),
      ...Object.keys(pkg.peerDependencies || {}),
    ],
    plugins,
  },
  // {
  //   input: "./src/js/index.mjs",
  //   output: {
  //     intro: "let ENVIRONMENT_IS_NODE = typeof process === 'object' && typeof process.versions === 'object' && typeof process.versions.node === 'string';",
  //     file: "dist/index.min.mjs",
  //     format: "esm",
  //   },
  //   // external: ["fs", "path", "crypto"],
  //   external: [
  //     ...Object.keys(pkg.dependencies || {}),
  //     ...Object.keys(pkg.peerDependencies || {}),
  //   ],
  //   plugins: plugins.concat(terser()),
  // },
];
