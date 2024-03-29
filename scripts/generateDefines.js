/*
Copyright NetFoundry, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import crypto from 'crypto';
import fs from 'fs';
import {globby} from 'globby';


(async () => {
    let define = [];
    let kdefine = {};
    const paths = await globby('./openssl/include/openssl/**/*.h');
    paths.forEach(p => {
        let headerSrc = fs.readFileSync(p, { encoding: 'utf8' });
        let defines = headerSrc.match(/#.?define.*/g);
        define = define.concat(defines);
    })

    let DEFINE_ARRAY = define
        .map(def => {
            if (def) {
                let cdef = def.replace(/.*#.?define /, '')
                    .split(/[\s\t]{1,}/).slice(0, 2)
                    .map(rquote => rquote.replace(/"/g, '')).filter(Boolean);
                if (cdef && cdef[1] && cdef[1].indexOf("/") > -1) {
                    cdef[1] = "";
                }
                if (!kdefine[cdef[0]]) {
                    kdefine[cdef[0]] = cdef[1];
                    if (kdefine[cdef[1]]) {
                        cdef[1] = kdefine[cdef[1]];
                    }
                    return cdef;
                }
            }
        }).filter(a =>
            a &&
            a.length &&
            !a[0].match(/\(|\)/g) &&
            a[1] && a[1].match &&
            !a[1].match(/\(|\)|\/|\\/g)).map(dae => {
                if (kdefine[dae[1]]) {
                    dae[1] = kdefine[dae[1]];
                }
                return dae;
            });


    DEFINE_ARRAY = DEFINE_ARRAY.map(ctext =>
        [ctext[0], parseFloat(ctext[1]) || `"${ctext[1]}"`].join(" = ")
    ).concat([
        "POINT_CONVERSION_COMPRESSED = 2",
        "POINT_CONVERSION_UNCOMPRESSED = 4",
        "POINT_CONVERSION_HYBRID = 6"
    ]);
    if (!fs.existsSync('./lib')) {
        fs.mkdirSync('./lib', { recursive: true });
    }
    fs.writeFileSync('./lib/define.mjs', `export const ${DEFINE_ARRAY.join(",\n")};`);
})();