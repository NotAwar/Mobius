import {
  enforceMobiusSentenceCasing,
  pluralize,
  strToBool,
  stripQuotes,
  isIncompleteQuoteQuery,
  hyphenateString,
} from "./stringUtils";

describe("string utilities", () => {
  describe("enforceMobiusSentenceCasing utility", () => {
    it("fixes a Title Cased String with no ignore words", () => {
      expect(enforceMobiusSentenceCasing("All Hosts")).toEqual("All hosts");
      expect(enforceMobiusSentenceCasing("all Hosts")).toEqual("All hosts");
      expect(enforceMobiusSentenceCasing("all hosts")).toEqual("All hosts");
      expect(enforceMobiusSentenceCasing("All HosTs ")).toEqual("All hosts");
    });

    it("fixes a title cased string while ignoring special words in various places ", () => {
      expect(enforceMobiusSentenceCasing("macOS")).toEqual("macOS");
      expect(enforceMobiusSentenceCasing("macOS Settings")).toEqual(
        "macOS settings"
      );
      expect(
        enforceMobiusSentenceCasing("osquery shouldn't be Capitalized")
      ).toEqual("osquery shouldn't be capitalized");
    });
    expect(enforceMobiusSentenceCasing("mobius uses MySQL")).toEqual(
      "Mobius uses MySQL"
    );
  });

  describe("pluralize utility", () => {
    it("returns the singular form of a word when count is 1", () => {
      expect(pluralize(1, "hero", "es", "")).toEqual("hero");
    });

    it("returns the plural form of a word when count is not 1", () => {
      expect(pluralize(0, "hero", "es", "")).toEqual("heroes");
      expect(pluralize(2, "hero", "es", "")).toEqual("heroes");
      expect(pluralize(100, "hero", "es", "")).toEqual("heroes");
    });

    it("returns the singular form of a word when count is 1 and a no custom suffix are provided", () => {
      expect(pluralize(1, "hero")).toEqual("hero");
    });

    it("returns the pluralized form of a word with 's' suffix when count is not 1 and no custom suffix are provided", () => {
      expect(pluralize(0, "hero")).toEqual("heros");
      expect(pluralize(2, "hero")).toEqual("heros");
      expect(pluralize(100, "hero")).toEqual("heros");
    });
  });

  describe("strToBool utility", () => {
    it("converts 'true' to true and 'false' to false", () => {
      expect(strToBool("true")).toBe(true);
      expect(strToBool("false")).toBe(false);
    });

    it("returns false for undefined, null, or empty string", () => {
      expect(strToBool(undefined)).toBe(false);
      expect(strToBool(null)).toBe(false);
      expect(strToBool("")).toBe(false);
    });
  });

  describe("stripQuotes utility", () => {
    it("removes matching single or double quotes from the start and end of a string", () => {
      expect(stripQuotes('"Hello, World!"')).toEqual("Hello, World!");
      expect(stripQuotes("'Hello, World!'")).toEqual("Hello, World!");
    });
    it("does not modify a string without quotes or mismatched quotes", () => {
      expect(stripQuotes("No quotes here")).toEqual("No quotes here");
      expect(stripQuotes(`'Mismatched quotes"`)).toEqual(`'Mismatched quotes"`);
    });
  });

  describe("isIncompleteQuoteQuery utility", () => {
    it("returns true for a string starting with a quote but not ending with one", () => {
      expect(isIncompleteQuoteQuery('"incomplete')).toBe(true);
      expect(isIncompleteQuoteQuery("'incomplete")).toBe(true);
    });

    it("returns false for a string with matching quotes", () => {
      expect(isIncompleteQuoteQuery('"complete"')).toBe(false);
      expect(isIncompleteQuoteQuery("'complete'")).toBe(false);
    });

    it("returns false for a string without any quotes or an empty string", () => {
      expect(isIncompleteQuoteQuery("no quotes")).toBe(false);
      expect(isIncompleteQuoteQuery("")).toBe(false);
    });
  });

  describe("hyphenatedTitle", () => {
    it("converts spaces to hyphens and lowercases", () => {
      expect(hyphenateString("My Cool App")).toBe("my-cool-app");
    });

    it("trims leading and trailing spaces", () => {
      expect(hyphenateString("   Leading and trailing   ")).toBe(
        "leading-and-trailing"
      );
    });

    it("collapses multiple spaces into one hyphen", () => {
      expect(hyphenateString("Multiple    spaces here")).toBe(
        "multiple-spaces-here"
      );
    });

    it("returns empty string for empty input", () => {
      expect(hyphenateString("")).toBe("");
    });

    it("handles already hyphenated and lowercase input", () => {
      expect(hyphenateString("already-hyphenated-title")).toBe(
        "already-hyphenated-title"
      );
    });

    it("handles single word", () => {
      expect(hyphenateString("Word")).toBe("word");
    });

    it("handles all uppercase", () => {
      expect(hyphenateString("ALL UPPERCASE")).toBe("all-uppercase");
    });

    it("handles mixed case and spaces", () => {
      expect(hyphenateString("  MixED CaSe   App ")).toBe("mixed-case-app");
    });

    it("handles numbers separated by spaces", () => {
      expect(hyphenateString("Numbered App 3")).toBe("numbered-app-3");
    });

    it("handles numbers attached to words", () => {
      expect(hyphenateString("Attached Numbered App3")).toBe(
        "attached-numbered-app3"
      );
    });
  });
});
