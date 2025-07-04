/* eslint-disable */
// @ts-nocheck
import {
  osqueryTableNames,
  osqueryTableColumnNames,
} from "utilities/osquery_tables";
import {
  sqlBuiltinFunctions,
  sqlDataTypes,
  sqlKeyWords,
} from "utilities/sql_tools";

ace.define(
  "ace/mode/mobius_highlight_rules",
  [
    "require",
    "exports",
    "module",
    "ace/lib/oop",
    "ace/mode/sql_highlight_rules",
  ],
  function (acequire, exports, module) {
    "use strict";

    var oop = acequire("../lib/oop");
    var SqlHighlightRules = acequire("./sql_highlight_rules").SqlHighlightRules;

    var MobiusHighlightRules = function () {
      var keywords = sqlKeyWords.join("|");

      var builtinConstants = "true|false";

      var builtinFunctions = sqlBuiltinFunctions.join("|");

      var dataTypes = sqlDataTypes.join("|");

      var osqueryTables = osqueryTableNames.join("|");
      var osqueryColumns = osqueryTableColumnNames.join("|");

      var keywordMapper = this.createKeywordMapper(
        {
          "osquery-token": osqueryTables,
          "osquery-column": osqueryColumns,
          "support.function": builtinFunctions,
          keyword: keywords,
          "constant.language": builtinConstants,
          "storage.type": dataTypes,
        },
        "identifier",
        true
      );

      this.$rules = {
        start: [
          {
            token: "comment",
            regex: "--.*$",
          },
          {
            token: "comment",
            start: "/\\*",
            end: "\\*/",
          },
          {
            token: "string", // " string
            regex: '".*?"',
          },
          {
            token: "string", // ' string
            regex: "'.*?'",
          },
          {
            token: "constant.numeric", // float
            regex: "[+-]?\\d+(?:(?:\\.\\d*)?(?:[eE][+-]?\\d+)?)?\\b",
          },
          {
            token: keywordMapper,
            regex: "[a-zA-Z_$][a-zA-Z0-9_$]*\\b",
          },
          {
            token: "keyword.operator",
            regex:
              "\\+|\\-|\\/|\\/\\/|%|<@>|@>|<@|&|\\^|~|<|>|<=|=>|==|!=|<>|=",
          },
          {
            token: "paren.lparen",
            regex: "[\\(]",
          },
          {
            token: "paren.rparen",
            regex: "[\\)]",
          },
          {
            token: "text",
            regex: "\\s+",
          },
        ],
      };

      this.normalizeRules();
    };

    oop.inherits(MobiusHighlightRules, SqlHighlightRules);

    exports.MobiusHighlightRules = MobiusHighlightRules;
  }
);

ace.define(
  "ace/mode/mobius",
  [
    "require",
    "exports",
    "module",
    "ace/lib/oop",
    "ace/mode/sql",
    "ace/mode/mobius_highlight_rules",
    "ace/range",
  ],
  function (acequire, exports, module) {
    "use strict";

    var oop = acequire("../lib/oop");
    var TextMode = acequire("./sql").Mode;
    var MobiusHighlightRules = acequire("./mobius_highlight_rules")
      .MobiusHighlightRules;
    var Range = acequire("../range").Range;

    var Mode = function () {
      this.HighlightRules = MobiusHighlightRules;
    };
    oop.inherits(Mode, TextMode);

    (function () {
      this.lineCommentStart = "--";

      this.$id = "ace/mode/mobius";
    }.call(Mode.prototype));

    exports.Mode = Mode;
  }
);
