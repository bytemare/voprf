```
 _        _______  _       
( \      (  ___  )( \      
| (      | (   ) || (      
| |      | |   | || |      
| |      | |   | || |      
| |      | |   | || |      
| (____/\| (___) || (____/\
(_______/(_______)(_______/
                           
```

Pull requests are accepted if they don't break any tests. LOL! 8-)

## Make me LOL ##

```
var lol = require('lol');
console.log(lol());
```

## TRANSFORMATIONALISATIONAL STREAMS IN YOUR FACE :-p ##

```
$ node -e "process.stdin.pipe(require('lol').transform).pipe(process.stdout)"
Hello, World!
wtf, lol!
^C
```

## MIDDLEWARE YO! ##

Adds an ```X-LOL``` header! <3

```
var lol = require('lol');
var app = express();
app.use(lol.middleware);
```

(Ends)
