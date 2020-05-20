# redis
Contains redis files

## Setup
Make sure you have redis installed. Once the repository is cloned, `cd` into the directory.
<br/> To install the dependencies, run
```
$ npm install
```

Before executing the program, first ensure that the redis server has started. Assuming ubuntu distro, run
```
$ redis-server
```

To start the server. If you are not using ubuntu, 
```
$ systemctl start redis
```
should be fine.

To start the node server, run
```
$ node ./bin/www
```


