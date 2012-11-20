// Copyright (c) 2012 Joyent, Inc.  All rights reserved.

function shuffle(array) {
        var current;
        var tmp;
        var top = array.length;

        if (top) {
                while (--top) {
                        current = Math.floor(Math.random() * (top + 1));
                        tmp = array[current];
                        array[current] = array[top];
                        array[top] = tmp;
                }
        }

        return (array);
}



///--- Exports

module.exports = {
        shuffle: shuffle
};