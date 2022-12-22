var stream = require('stream');

var exclamations = [
    'lol',
    'rofl',
    'wtf',
    'OMG',
    'OMGWTFBBQ',
    'O RLY?',
    'YA RLY!',
    '<3',
    'wut!',
    'hipster',
];
var length = exclamations.length;

function lol() {
    var i = parseInt(Math.random()*length, 10);
    return exclamations[i];
};

lol.middleware = function(req, res, next) {
    res.set('X-LOL', lol());
    next();
};

lol.transform = new stream.Transform({ objectMode : true });
lol.transform._transform = function _transform(msg, encoding, done) {
    this.push(msg.toString('utf8').replace(/\w+/g, function (match) { return lol(); }));
    done();
};

module.exports = lol;
