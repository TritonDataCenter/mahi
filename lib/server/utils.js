/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2026 Edgecast Cloud LLC.
 */

/**
 * Utility functions for Mahi
 */

/**
 * Create hexdump output (like xxd)
 */
function hexdump(str) {
    if (typeof (str) !== 'string') {
            throw new Error('hexdump input must be a string');
        }
        if (str.length > 1048576) { // 1MB limit for hexdump
            throw new Error('String too large for hexdump (max 1MB)');
        }
        var buf = new Buffer(str, 'utf8');
        var result = '';
        var offset = 0;

        for (var i = 0; i < buf.length; i += 16) {
                // Offset column (8 chars, zero-padded hex)
                var offsetStr = ('0000000' + offset.toString(16)).slice(-8);
                result += offsetStr + ': ';

                // Hex bytes (16 bytes per line, grouped by 2)
                var hexLine = '';
                var asciiLine = '';

                for (var j = 0; j < 16; j++) {
                        if (i + j < buf.length) {
                                var cbyte = buf[i + j];
                                var hex = ('0' + cbyte.toString(16)).slice(-2);
                                hexLine += hex;
                                // ASCII representation (printable chars only)
                                if (cbyte >= 32 && cbyte <= 126) {
                                        asciiLine += String.fromCharCode(cbyte);
                                } else {
                                        asciiLine += '.';
                                }
                        } else {
                                hexLine += '  ';
                                asciiLine += ' ';
                        }
                        // Add space every 2 bytes
                        if (j % 2 === 1) {
                                hexLine += ' ';
                        }
                }
                result += hexLine + ' ' + asciiLine + '\n';
                offset += 16;
        }

        return (result);
}

module.exports = {
        hexdump: hexdump
};
