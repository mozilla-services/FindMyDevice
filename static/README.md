# Find My Device: Front-end

The Find My Device front-end toolkit is powered by node, grunt, and bower, so you'll need to get yourself node >=0.10.0 with npm. It's also a good idea to have global installs of grunt (`npm install -g grunt`) and bower (`npm install -g bower`). Once you have those fine tools, `npm install` should get you going.

## Development

When developing, it is recommended that you use `grunt watch` to transform `.scss` files into `.css` files. The `css` files are stored in git to make server side development simpler. Please commit both when making any style changes.

## Localization

### Extracting strings

- `grunt l10n-extract` will create `./locale/templates`
- `client.pot` and `server.pot` can then be merged into the [FindMyDevice-l10n](https://github.com/mozilla-services/FindMyDevice-l10n) repository.

### Importing strings

- Strings are fetched from the [FindMyDevice-l10n](https://github.com/mozilla-services/FindMyDevice-l10n) repo using bower.
- `grunt build` will copy and convert the `.po` files into an easily consumable json format.
- The converted json files can be found in `app/l10n` and `dist/l10n`.
- `l10n/*/server.json` contains strings for the server side (`index.html`).
- `l10n/*/client.json` contains strings for the front-end app (mustache templates and js files).

## Testing

Right now the test suite consists of entirely functional tests that require Selenium. It is also required that you run Phony (`./test/phony.js`), our happy device simulator. Use `../config-travis.ini` as a starting point for getting the test environment working with the Find My Device server. See project [README](../README.md) for details about running the server.

### Prerequisites:

  * Java JDK or JRE (http://www.oracle.com/technetwork/java/javase/downloads/index.html)
  * Selenium Server (http://docs.seleniumhq.org/download/)

### Running the tests

Start each of these in separate terminal windows (tabs):

  * Find My Device server running from the project root: `cd .. && ./runserver.bash`
  * Phony: `node test/phony.js`
  * Selenium: `java -jar /path/to/download/selenium-server-standalone-2.38.0.jar`
  * Start the tests: `npm test`

## Production

When deploying Find My Device in a production environment, use `grunt build` to produce concatenated and minified assets in the `dist` directory. This is highly recommended. The server can be configured to use this directory using `document_root` in `config.ini`.
