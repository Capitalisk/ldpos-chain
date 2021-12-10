# ldpos-chain
Simple DPoS chain module compatible with LDEX

## Running tests using mock DAL
```shell script
yarn test
```

## Running tests using pg DAL
- Start postgres inside docker container
```shell script
./scripts/start-postgres.sh
```

- Run pg-dal tests
```shell script
  yarn test:using-pg-dal
```

- Stop postgres
```shell script
./scripts/stop-postgres.sh
```

## License

The license is `GPL-3.0` with one additional condition:
Misrepresenting the origin of this code or code derived from it is not permitted.
