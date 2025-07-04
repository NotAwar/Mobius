module.exports = {


  friendlyName: 'Get extended osquery schema',


  description: 'Get the extended osquery schema and documentation supported by Mobius by reading the raw osquery tables and Mobius\'s overrides from disk, then returning the extended set of tables.',

  inputs: {
    includeLastModifiedAtValue: {
      type: 'boolean',
      defaultsTo: false,
      description: 'Whether or not to include a lastModifiedAt value for each table.',
    },
    githubAccessToken: {
      type: 'string',
      description: 'A github token used to authenticate requests to the GitHub API'
    }
  },

  exits: {

    success: {
      outputFriendlyName: 'Extended tables',
      outputType: [ {} ],
    }


  },


  fn: async function ({includeLastModifiedAtValue, githubAccessToken}) {
    let path = require('path');
    let YAML = require('yaml');
    let util = require('util');
    let topLvlRepoPath = path.resolve(sails.config.appPath, '../');
    require('assert')(sails.config.custom.versionOfOsquerySchemaToUseWhenGeneratingDocumentation, 'Please set sails.config.custom.sails.config.custom.versionOfOsquerySchemaToUseWhenGeneratingDocumentation to the version of osquery to use, for example \'5.8.1\'.');
    let VERSION_OF_OSQUERY_SCHEMA_TO_USE = sails.config.custom.versionOfOsquerySchemaToUseWhenGeneratingDocumentation;

    // Getting the specified osquery schema from the osquery/osquery-site GitHub repo.
    let rawOsqueryTables = await sails.helpers.http.get('https://raw.githubusercontent.com/osquery/osquery-site/source/src/data/osquery_schema_versions/'+VERSION_OF_OSQUERY_SCHEMA_TO_USE+'.json');

    let rawOsqueryTablesLastModifiedAt;
    if(includeLastModifiedAtValue) {
      // If we're including a lastModifiedAt value for schema tables, we'll send a request to the GitHub API to get a timestamp of when the last commit
      let baseHeadersForGithubRequests = {
        'User-Agent': 'mobius-schema-builder',
        'Accept': 'application/vnd.github.v3+json',
      };
      // If a GitHub access token was provided, add it to the headers.
      if(githubAccessToken){
        baseHeadersForGithubRequests['Authorization'] = `token ${githubAccessToken}`;
      }
      let responseData = await sails.helpers.http.get.with({// [?]: https://docs.github.com/en/rest/commits/commits?apiVersion=2022-11-28#list-commits
        url: 'https://api.github.com/repos/osquery/osquery-site/commits',
        data: {
          path: '/src/data/osquery_schema_versions/'+VERSION_OF_OSQUERY_SCHEMA_TO_USE+'.json',
          page: 1,
          per_page: 1,//eslint-disable-line camelcase
        },
        headers: baseHeadersForGithubRequests
      }).intercept((err)=>{
        return new Error(`When trying to send a request to GitHub get a timestamp of the last commit to the osqeury schema JSON, an error occurred. Full error: ${util.inspect(err)}`);
      });
      // The value we'll use for the lastModifiedAt timestamp will be date value of the `commiter` property of the `commit` we got in the API response from github.
      let mostRecentCommitToOsquerySchema = responseData[0];
      if(!mostRecentCommitToOsquerySchema.commit || !mostRecentCommitToOsquerySchema.commit.committer) {
        // Throw an error if the the response from GitHub is missing a commit or commiter.
        throw new Error(`When trying to get a lastModifiedAt timestamp for the osqeury schema json, the response from the GitHub API did not include information about the most recent commit. Response from GitHub: ${util.inspect(responseData, {depth:null})}`);
      }
      rawOsqueryTablesLastModifiedAt = (new Date(mostRecentCommitToOsquerySchema.commit.committer.date)).getTime(); // Convert the UTC timestamp from GitHub to a JS timestamp.
    }
    let mobiusOverridesForTables = [];

    let filesInTablesFolder = await sails.helpers.fs.ls(path.resolve(topLvlRepoPath+'/schema/tables'));

    let yamlSchemaInTablesFolder = filesInTablesFolder.filter((filename)=>{return _.endsWith(filename, '.yml');});

    for(let yamlSchema of yamlSchemaInTablesFolder) {
      let tableYaml = await sails.helpers.fs.read(yamlSchema);
      let parsedYamlTable;
      try {
        parsedYamlTable = YAML.parse(tableYaml, {prettyErrors: true});
      } catch(err) {
        throw new Error(`Could not parse the Mobius overrides YAMl at ${yamlSchema} on line ${err.linePos.start.line}. To resolve, make sure the YAML is valid, then try running this script again: `+err.stack);
      }

      if(includeLastModifiedAtValue) {
        // If we're including lastModifiedAt values, we'll use git to get a timestamp representing when the yaml
        // file was last changed, and add it to the parsedYamlTable object.
        let lastModifiedAt = (new Date((await sails.helpers.process.executeCommand.with({
          command: `git log -1 --format="%ai" '${path.relative(topLvlRepoPath, yamlSchema)}'`,
          dir: topLvlRepoPath,
        })).stdout)).getTime();
        parsedYamlTable.lastModifiedAt = lastModifiedAt;
      }

      if(parsedYamlTable.name) {
        if(typeof parsedYamlTable.name !== 'string') {
          throw new Error(`Could not merge osquery schema with Mobius overrides. A table in the Mobius overrides schema has an invalid "name" (Expected a string, but instead got a ${typeof parsedYamlTable.name}. To resolve, change the "name" of the table located at ${yamlSchema} to be a string.`);
        }
        mobiusOverridesForTables.push(parsedYamlTable);
      } else { // Throw an error if a Mobius override table is missing a "name".
        throw new Error(`Could not merge osquery schema with Mobius overrides. A table in the Mobius overrides schema is missing a "name". To resolve, add a "name" to the Mobius override table located at ${yamlSchema}.`);
      }
    }

    let expandedTables = []; // create an empty array for the merged schema.

    for(let osquerySchemaTable of rawOsqueryTables) {

      let mobiusOverridesForTable = _.find(mobiusOverridesForTables, {'name': osquerySchemaTable.name}); // Setting a flag if this table exists in the Mobius overrrides JSON
      let expandedTableToPush = _.clone(osquerySchemaTable);

      if(!mobiusOverridesForTable) {
        if(_.endsWith(osquerySchemaTable.name, '_events')) {// Make sure that all tables that have names ending in '_events' have evented: true
          expandedTableToPush.evented = true;// FUTURE: fix this in the main osquery schema so that they always have evented: true
        }
        if(expandedTableToPush.url) { // Set the osqueryRepoUrl to be the table's original url.
          expandedTableToPush.osqueryRepoUrl = expandedTableToPush.url;
        }
        // Set the URL of the table to be the table's page on mobiusmdm.com
        expandedTableToPush.url = 'https://mobiusmdm.com/tables/'+encodeURIComponent(expandedTableToPush.name);
        // Since we don't have a Mobius override for this table, we'll set the mobiusRepoUrl for this table to be a link to create the Mobius override table YAML.
        // This is done by adding a 'filename' and 'value' as search parameters to a url that creates a new folder in the schema/tables/ folder.
        let sampleYamlSchemaForThisTable =`name: ${expandedTableToPush.name}\ndescription: |- # (required) string - The description for this table. Note: this field supports Markdown\n\t# Add description here\nexamples: |- # (optional) string - An example query for this table. Note: This field supports Markdown\n\t# Add examples here\nnotes: |- # (optional) string - Notes about this table. Note: This field supports Markdown.\n\t# Add notes here\ncolumns: # (required)\n\t- name: # (required) string - The name of the column\n\t  description: # (required) string - The column's description. Note: this field supports Markdown\n\t  type: # (required) string - the column's data type\n\t  required: # (required) boolean - whether or not this column is required to query this table.`;

        expandedTableToPush.mobiusRepoUrl = 'https://github.com/notawar/mobius/new/main/schema?filename='+encodeURIComponent('tables/'+expandedTableToPush.name)+'.yml&value='+encodeURIComponent(sampleYamlSchemaForThisTable);

        // As the table might have multiple examples, we grab only one until we
        // adjust the UI to better display multiple examples (paddings, UX,
        // etc.)
        //
        // We pick the last example in the array as they progressively build in
        // complexity and the last is usually the richest.
        //
        // TODO: adjust the UI to show all examples.
        let examplesFromOsquerySchema = expandedTableToPush.examples;
        if (examplesFromOsquerySchema.length > 0) {
          // Examples are parsed as markdown, so we wrap the example in a code
          // fence so it renders as a code block.
          expandedTableToPush.examples = '```\n' + examplesFromOsquerySchema[examplesFromOsquerySchema.length - 1] + '\n```';
        } else {
          // If this table has an examples value that is an empty array, we'll completly remove it from the merged schema.
          delete expandedTableToPush.examples;
        }
        if(includeLastModifiedAtValue) {
          expandedTableToPush.lastModifiedAt = rawOsqueryTablesLastModifiedAt;
        }
        expandedTables.push(expandedTableToPush);
      } else { // If this table exists in the Mobius overrides schema, we'll override the values
        if(mobiusOverridesForTable.platforms !== undefined) {
          if(!_.isArray(mobiusOverridesForTable.platforms)) {
            throw new Error(`Could not merge osquery schema with Mobius overrides. The Mobius override for the "${mobiusOverridesForTable.name}" table located at ${path.resolve(topLvlRepoPath+'/schema/tables', mobiusOverridesForTable.name+'.yml')} has an invalid "platforms" value. To resolve, change the "platforms" for this table to be an array of values.`);
          } else{
            expandedTableToPush.platforms = _.clone(mobiusOverridesForTable.platforms);
          }
        }
        if(mobiusOverridesForTable.description !== undefined){
          if(typeof mobiusOverridesForTable.description !== 'string') {
            throw new Error(`Could not merge osquery schema with Mobius overrides. The Mobius override for the "${mobiusOverridesForTable.name}" table located at ${path.resolve(topLvlRepoPath+'/schema/tables', mobiusOverridesForTable.name+'.yml')} has an invalid "description". To resolve, change the "description" for this table to be a string.`);
          } else {
            expandedTableToPush.description = _.clone(mobiusOverridesForTable.description);
          }
        }
        if(mobiusOverridesForTable.examples !== undefined) {
          if(typeof mobiusOverridesForTable.examples !== 'string') {
            throw new Error(`Could not merge osquery schema with Mobius overrides. The Mobius override for the "${mobiusOverridesForTable.name}" table located at ${path.resolve(topLvlRepoPath+'/schema/tables', mobiusOverridesForTable.name+'.yml')} has an invalid "examples". To resolve, change the "examples" for this table to be a string.`);
          } else {
            expandedTableToPush.examples = _.clone(mobiusOverridesForTable.examples);
          }
        } else {
          // If the override file does not contain an 'examples' value, we'll use the last example from the osquery schema (See above for more information about the reasoning behind this)
          let examplesFromOsquerySchema = expandedTableToPush.examples;
          if (examplesFromOsquerySchema.length > 0) {
            // Examples are parsed as markdown, so we wrap the example in a code fence so it renders as a code block.
            expandedTableToPush.examples = '```\n' + examplesFromOsquerySchema[examplesFromOsquerySchema.length - 1] + '\n```';
          } else {
            // If this table has an examples value that is an empty array, we'll completly remove it from the merged schema.
            delete expandedTableToPush.examples;
          }
        }
        if(mobiusOverridesForTable.notes !== undefined) {
          if(typeof mobiusOverridesForTable.notes !== 'string') {
            throw new Error(`Could not merge osquery schema with Mobius overrides. The Mobius override for the "${mobiusOverridesForTable.name}" table located at ${path.resolve(topLvlRepoPath+'/schema/tables', mobiusOverridesForTable.name+'.yml')} has an invalid "notes". To resolve, change the "notes" for this table to be a string.`);
          } else {
            expandedTableToPush.notes = _.clone(mobiusOverridesForTable.notes);
          }
        }
        if(mobiusOverridesForTable.hidden !== undefined) {
          if(typeof mobiusOverridesForTable.hidden !== 'boolean') {
            throw new Error(`Could not merge osquery schema with Mobius overrides. The Mobius override for the "${mobiusOverridesForTable.name}" table located at ${path.resolve(topLvlRepoPath+'/schema/tables', mobiusOverridesForTable.name+'.yml')} has an invalid "hidden" value. To resolve, change the value of the "hidden" property for this table to be a boolean.`);
          } else {
            expandedTableToPush.hidden = _.clone(mobiusOverridesForTable.hidden);
          }
        }
        // If the table has Mobius overrides, we'll add the URL of the YAML file in the Mobius Github repo as the `mobiusRepoUrl`, and add set the url to be where this table will live on mobiusmdm.com.
        expandedTableToPush.mobiusRepoUrl = 'https://github.com/notawar/mobius/blob/main/schema/tables/'+encodeURIComponent(expandedTableToPush.name)+'.yml';
        expandedTableToPush.url = 'https://mobiusmdm.com/tables/'+encodeURIComponent(expandedTableToPush.name);
        // If we're including lastModifiedAt values, we'll set the value for this table to be when the Mobius override was last modified.
        if(includeLastModifiedAtValue) {
          expandedTableToPush.lastModifiedAt = mobiusOverridesForTable.lastModifiedAt;
        }
        let mergedTableColumns = [];
        for (let osquerySchemaColumn of osquerySchemaTable.columns) { // iterate through the columns in the osquery schema table
          if(!mobiusOverridesForTable.columns) { // If there are no column overrides for this table, we'll add the column unchanged.
            if(osquerySchemaColumn.platforms !== undefined) {// If the column in the osquery schema has a platforms value, we'll normalize the names
              let platformWithNormalizedNames = [];
              for(let platform of osquerySchemaColumn.platforms) {
                if(platform === 'darwin') {// darwin » macOS
                  platformWithNormalizedNames.push('macOS');
                } else if(platform === 'windows' || platform === 'linux') {// Note: we're ignoring all other platform values (e.g, win32 and cygwin).
                  platformWithNormalizedNames.push(_.capitalize(platform));
                }
              }
              osquerySchemaColumn.platforms = platformWithNormalizedNames;
            }
            mergedTableColumns.push(osquerySchemaColumn);
          } else {// If the Mobius overrides JSON has column data for this table, we'll find the matching column and use the values from the Mobius overrides in the final schema.
            let columnHasMobiusOverrides = _.find(mobiusOverridesForTable.columns, {'name': osquerySchemaColumn.name});
            if(!columnHasMobiusOverrides) {// If this column has no Mobius overrides, we'll add it to the final schema unchanged
              mergedTableColumns.push(osquerySchemaColumn);
            } else { // If this table has Mobius overrides, we'll adjust the value in the merged schema
              let mobiusColumn = _.clone(osquerySchemaColumn);
              if(columnHasMobiusOverrides.platforms !== undefined) {
                let platformWithNormalizedNames = [];
                for(let platform of columnHasMobiusOverrides.platforms) {
                  if(platform === 'darwin') {
                    platformWithNormalizedNames.push('macOS');
                  } else if(platform === 'chrome') {
                    platformWithNormalizedNames.push('ChromeOS');
                  } else {
                    platformWithNormalizedNames.push(_.capitalize(platform));
                  }
                }
                mobiusColumn.platforms = platformWithNormalizedNames;
              }
              if(columnHasMobiusOverrides.description !== undefined) {
                if(typeof columnHasMobiusOverrides.description === 'string') {
                  mobiusColumn.description = _.clone(columnHasMobiusOverrides.description);
                } else {
                  mobiusColumn.description = '';
                }
              }
              if(columnHasMobiusOverrides.type !== undefined) {
                mobiusColumn.type = _.clone(columnHasMobiusOverrides.type.toLowerCase());
              }
              if(columnHasMobiusOverrides.required !== undefined) {
                mobiusColumn.required = _.clone(columnHasMobiusOverrides.required);
              }
              if(columnHasMobiusOverrides.hidden !== true) { // If the overrides don't explicitly hide a column, we'll set the value to false to make sure the column is visible on mobiusmdm.com
                mobiusColumn.hidden = false;
              }
              mergedTableColumns.push(mobiusColumn);
            }
          }
        }//∞ After each column in osquery schema table

        // Now iterate through the columns in the Mobius overrides, adding any columns that doesnt exist in the base osquery schema.
        if(mobiusOverridesForTable.columns) {
          if(!_.isArray(mobiusOverridesForTable.columns)){
            throw new Error(`The osquery schema could not be merged with the Mobius overrrides. The "${mobiusOverridesForTable.name}" table in Mobius's overrides has an invalid "columns". To resolve, change the "columns" to be an array of objects (each containing values for "name", "type", "description" and "required" properties), and try running the script again.`);
          }
          for(let mobiusOverrideColumn of mobiusOverridesForTable.columns) {
            if(!mobiusOverrideColumn.name) {
              throw new Error(`The osquery schema could not be merged with the Mobius overrides. A column in the "${mobiusOverridesForTable.name}" is missing a "name". To resolve, make sure every column in /schema/tables/${mobiusOverridesForTable.name}.yml has a "name" property`);
            }
            let columnExistsInBothSchemas = _.find(osquerySchemaTable.columns, {'name': mobiusOverrideColumn.name});
            if(!columnExistsInBothSchemas) {
              let overrideColumnToAdd = _.clone(mobiusOverrideColumn);
              // Make sure the column we're adding has all the information we need, if it is missing a description or a type, we'll throw an error.

              if(overrideColumnToAdd.description) {
                if (typeof overrideColumnToAdd.description !== 'string') {
                  throw new Error(`The osquery tables could not be merged with the Mobius overrides. The "description" for the "${mobiusOverrideColumn.name}" column of the "${mobiusOverridesForTable.name}" table is an invalid type (${typeof mobiusOverrideColumn.name}). to resolve, change the column's "description" to be a string.`);
                }//•
              } else {
                throw new Error(`The osquery tables could not be merged with the Mobius overrides. The "${mobiusOverrideColumn.name}" column added to the merged schema for the "${mobiusOverridesForTable.name}" table is missing a description in the Mobius overrides schema. To resolve, add a description for this column to the Mobius overrides schema.`);
              }

              if(overrideColumnToAdd.type) {
                if(typeof overrideColumnToAdd.type !== 'string') {
                  throw new Error(`The osquery tables could not be merged with the Mobius overrides. The "type" for the "${mobiusOverrideColumn.name}" column of the "${mobiusOverridesForTable.name}" table is an invalid type (${typeof mobiusOverrideColumn.type}). To resolve, change the value of a column's "type" to be a string.`);
                }//•
                overrideColumnToAdd.type = overrideColumnToAdd.type.toLowerCase();
              } else {
                throw new Error(`The osquery tables could not be merged with the Mobius overrides. The "${mobiusOverrideColumn.name}" column added to the merged schema for the "${mobiusOverridesForTable.name}" table is missing a "type" in the Mobius overrides schema. To resolve, add a type for this column to the Mobius overrides schema.`);
              }

              if(overrideColumnToAdd.platforms) {
                if(!_.isArray(overrideColumnToAdd.platforms)) {
                  throw new Error(`The osquery tables could not be merged with the Mobius overrides. The "platforms" property of the "${overrideColumnToAdd.name}" column of the "${mobiusOverridesForTable.name}" table has an invalid value. To resolve, change the "platforms" of this column to an array`);
                }//•
              }

              if(overrideColumnToAdd.required === undefined) {
                throw new Error(`The osquery tables could not be merged with the Mobius overrides. The "${mobiusOverrideColumn.name}" column added in the Mobius overrides for the "${mobiusOverridesForTable.name}" table is missing a "required" value. To resolve, add a "required" value (a boolean) to the column in Mobius's overrides at ${path.resolve(topLvlRepoPath+'/schema/tables', mobiusOverridesForTable.name+'.yml')}`);
              } else if(typeof overrideColumnToAdd.required !== 'boolean') {
                throw new Error(`The osquery tables could not be merged with the Mobius overrides. The "${mobiusOverrideColumn.name}" column added in the Mobius overrides for the "${mobiusOverridesForTable.name}" table has an invalid "required" value. To resolve, change the value of the "required" property for this to the column in Mobius's overrides at ${path.resolve(topLvlRepoPath+'/schema/tables', mobiusOverridesForTable.name+'.yml')} to be either "true" or "false"`);
              }

              mergedTableColumns.push(overrideColumnToAdd);
            }
          }//∞ After each column in Mobius overrides table
        }
        expandedTableToPush.columns = mergedTableColumns;
        expandedTables.push(expandedTableToPush);
      }
    }//∞ After each table in osquery schema

    // After we've gone through the tables in the Osquery schema, we'll go through the tables in the Mobius schema JSON, and add any tables that don't exist in the osquery schema.
    for (let mobiusOverridesForTable of mobiusOverridesForTables) {
      let mobiusOverrideToPush = _.clone(mobiusOverridesForTable);
      if(!mobiusOverrideToPush.name){
        throw new Error(`A table in the Mobius overrides schema is missing a 'name' (${JSON.stringify(mobiusOverrideToPush)}). To resolve, make sure this table has a "name" property.`);
      }
      let mobiusSchemaTableExistsInOsquerySchema = _.find(rawOsqueryTables, (table)=>{
        return mobiusOverrideToPush.name === table.name;
      });
      if(!mobiusSchemaTableExistsInOsquerySchema) { // If a table in the Mobius schema does not exist in the osquery schema, we'll add it to the final schema after making sure that it has the required values.

        if(!mobiusOverrideToPush.description) {
          throw new Error(`Could not add a new table from the Mobius overrides to final merged schema, the "${mobiusOverrideToPush.name}" table is missing a 'description' value. To resolve, add a description to this table to the Mobius overrides schema at ${path.resolve(topLvlRepoPath+'/schema/tables', mobiusOverrideToPush.name+'.yml')}. Tip: If this table is meant to override a table in the osquery schema, you may want to check that the "name" value of the added table is the same as the table in the osquery schema located at https://github.com/osquery/osquery-site/source/src/data/osquery_schema_versions/${VERSION_OF_OSQUERY_SCHEMA_TO_USE}.json`);
        } else if(typeof mobiusOverrideToPush.description !== 'string'){
          throw new Error(`Could not add a new table from the Mobius overrides to final merged schema, The "description" of the "${mobiusOverridesForTable.name}" table is an invalid type (Eexpected a string, but instead got a ${typeof mobiusOverrideToPush.description}). to resolve, change the tables's "description" to be a string.`);
        }
        if(!mobiusOverrideToPush.platforms) {
          throw new Error(`Could not add a new table from the Mobius overrides to final merged schema, the "${mobiusOverrideToPush.name}" table is missing a 'platforms' value. To resolve, add an array of platforms to this table to the Mobius overrides schema at ${path.resolve(topLvlRepoPath+'/schema/tables', mobiusOverrideToPush.name+'.yml')}. Tip: If this table is meant to override a table in the osquery schema, you may want to check that the "name" value of the added table is the same as the table in the osquery schema located at https://github.com/osquery/osquery-site/source/src/data/osquery_schema_versions/${VERSION_OF_OSQUERY_SCHEMA_TO_USE}.json`);
        } else if(!_.isArray(mobiusOverrideToPush.platforms)) {
          throw new Error(`Could not add a new table from the Mobius overrides to final merged schema, the "${mobiusOverrideToPush.name}" table has an invalid 'platforms' value. (expected an array, but instead got a ${typeof mobiusOverrideToPush.platforms}) To resolve, change the "platforms" value to be an array of values, then try runing this script again.`);
        }
        if(mobiusOverrideToPush.evented === undefined) {
          throw new Error(`Could not add a new table from the Mobius overrides to final merged schema, the "${mobiusOverrideToPush.name}" table is missing a 'evented' value. To resolve, add an evented value to this table to the Mobius overrides schema at ${path.resolve(topLvlRepoPath+'/schema/tables', mobiusOverrideToPush.name+'.yml')} .\n Tip: If this table is meant to override a table in the osquery schema, you may want to check that the "name" value of the added table is the same as the table in the osquery schema https://github.com/osquery/osquery-site/source/src/data/osquery_schema_versions/${VERSION_OF_OSQUERY_SCHEMA_TO_USE}.json`);
        } else if(typeof mobiusOverrideToPush.evented !== 'boolean') {
          throw new Error(`Could not add a new table from the Mobius overrides to the final merged schema. The "${mobiusOverrideToPush.name}" table has an invalid "evented" value. (expected a boolean, but instead got a ${typeof mobiusOverrideToPush.evented}) To resolve, change the "evented" value for this table to be true or false, then try running this script again.`);
        }
        if(!mobiusOverrideToPush.columns) {
          throw new Error(`Could not add a new table from the Mobius overrides to final merged schema. The "${mobiusOverrideToPush.name}" table is missing a "columns" value. To resolve, add an array of columns to this table to the Mobius overrides schema at ${path.resolve(topLvlRepoPath+'/schema/tables', mobiusOverrideToPush.name+'.yml')}. Tip: If this table is meant to override a table in the osquery schema, you may want to check that the "name" value of the added table is the same as the table in the osquery schema located at https://github.com/osquery/osquery-site/source/src/data/osquery_schema_versions/${VERSION_OF_OSQUERY_SCHEMA_TO_USE}.json`);
        } else if(!_.isArray(mobiusOverrideToPush.columns)){
          throw new Error(`Could not add a new table from the Mobius overrides to final merged schema, the "${mobiusOverrideToPush.name}" table has an invalid "columns" value. (Expected an array, but instead got a ${typeof mobiusOverrideToPush.columns}) To resolve, change the "columns" value to be an array of values, then try runing this script again.`);
        } else {

          for(let columnToValidate of mobiusOverrideToPush.columns) { // Check each column in the table to make sure it has the required values, and that all values are the correct type.

            if(!columnToValidate.name) {
              throw new Error(`Could not add a new table from the Mobius overrides schema. A column in the "${mobiusOverrideToPush.name}" table is missing a "name". To resolve, make sure every column in the table located at ${path.resolve(topLvlRepoPath+'/schema/tables', mobiusOverrideToPush.name+'.yml')} has a "name" property.`);

            } else if(typeof columnToValidate.name !== 'string') {
              throw new Error(`Could not add a new table from the Mobius overrides schema. A column in the "${mobiusOverrideToPush.name}" table located at /schema/tables/${mobiusOverrideToPush.name}.yml has an invalid "name" (expected a string, but instead got ${typeof columnToValidate.name}).\nTo resolve, make sure that the "name" of every column in this table is a string.`);
            }//•

            if(!columnToValidate.type) {
              throw new Error(`Could not add a new table from the Mobius overrides schema. The "${columnToValidate.name}" column of the "${mobiusOverrideToPush.name}" table is missing a "type". To resolve add a "type" to the "${columnToValidate.name}" column at ${path.resolve(topLvlRepoPath+'/schema/tables', mobiusOverrideToPush.name+'.yml')}.`);
            } else if(typeof columnToValidate.type !== 'string') {
              throw new Error(`Could not add a table from the Mobius overrides schema. The "type" of the "${columnToValidate.name}" column of the "${mobiusOverrideToPush.name}" table at ${path.resolve(topLvlRepoPath+'/schema/tables', mobiusOverrideToPush.name+'.yml')} has an invalid value. (expected a string, but got a ${typeof columnToValidate.type}) To resolve, change the value of the column's "type" be a string.`);
            }//•
            columnToValidate.type = columnToValidate.type.toLowerCase();

            if(!columnToValidate.description) {
              throw new Error(`Could not add a new table from the Mobius overrides schema. The "${columnToValidate.name}" column of the "${mobiusOverrideToPush.name}" table is missing a "description". To resolve add a "description" property to the "${columnToValidate.name}" column at ${path.resolve(topLvlRepoPath+'/schema/tables', mobiusOverrideToPush.name+'.yml')}`);
            } else if (typeof columnToValidate.description !== 'string') {
              throw new Error(`Could not add a table from the Mobius overrides schema. The "description" property of the "${columnToValidate.name}" column of the "${mobiusOverrideToPush.name}" table at ${path.resolve(topLvlRepoPath+'/schema/tables', mobiusOverrideToPush.name+'.yml')} has an invalid "description" value. To resolve, change the "description" property of the added column to be a string.`);
            }//•

            if(columnToValidate.required === 'undefined') {
              throw new Error(`Could not add a new table from the Mobius overrides schema. The "${columnToValidate.name}" column of the "${mobiusOverrideToPush.name}" table is missing a "required" property. To resolve add a "required" property to the "${columnToValidate.name}" column at ${path.resolve(topLvlRepoPath+'/schema/tables', mobiusOverrideToPush.name+'.yml')}`);
            } else if (typeof columnToValidate.required !== 'boolean') {
              throw new Error(`Could not add a new table from the Mobius overrides schema. The "${columnToValidate.name}" column of the "${mobiusOverrideToPush.name}" table has an invalid "required" value. (expected a boolean, but instead got a ${typeof columnToValidate.required}) To resolve, change the "required" property of the added column to be a boolean.`);
            }//•

            if(columnToValidate.platforms) {
              if(!_.isArray(columnToValidate.platforms)){
                throw new Error(`Could not add a new table from the Mobius overrides schema. The "platforms" property of the "${columnToValidate.name}" column of the "${mobiusOverrideToPush.name}" table has an invalid value. To resolve, change the "platforms" of this column to an array`);
              }//•
            }
          }//∞ After each column in Mobius overrides table
        }
        // After we've made sure that this table has all the required values, we'll add the url of the table's YAML file in the Mobius GitHub repo as the `mobiusRepoUrl`  and the location of this table on mobiusmdm.com as the `url` before adding it to our merged schema.
        mobiusOverrideToPush.url = 'https://mobiusmdm.com/tables/'+encodeURIComponent(mobiusOverrideToPush.name);
        mobiusOverrideToPush.mobiusRepoUrl = 'https://github.com/notawar/mobius/blob/main/schema/tables/'+encodeURIComponent(mobiusOverrideToPush.name)+'.yml';
        expandedTables.push(mobiusOverrideToPush);
      }//∞ After each Mobius overrides table
    }
    // Sort the merged tables by table name
    let sortedMergedSchema = _.sortBy(expandedTables, 'name');
    // Return the sorted merged schema
    return sortedMergedSchema;
  }

};

