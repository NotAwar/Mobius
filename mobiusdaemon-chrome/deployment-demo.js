#!/usr/bin/env node

/**
 * Demo script simulating the full GitHub Actions workflow
 * This helps verify the extension can be built and deployed
 */

const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

console.log("🚀 Starting Chrome Extension Deployment Demo...");

try {
  // Step 1: Install dependencies
  console.log("\n📦 Installing dependencies...");
  execSync("npm install --no-save", { stdio: "inherit" });

  // Step 2: Run tests
  console.log("\n🧪 Running tests...");
  execSync("npm test", { stdio: "inherit" });

  // Step 3: Verify service
  console.log("\n🔍 Verifying service...");
  execSync("npm run verify", { stdio: "inherit" });

  // Step 4: Build extension
  console.log("\n🏗️  Building extension...");
  execSync("npm run build", { stdio: "inherit" });

  // Step 5: Simulate setting version
  console.log("\n🔖 Setting version...");
  const pkg = JSON.parse(fs.readFileSync("package.json", "utf8"));
  console.log(`Version: ${pkg.version}`);

  // Step 6: Check built files
  console.log("\n📁 Checking built files...");
  const builtFiles = ["dist/background.js", "dist/content.js", "dist/popup.html", "dist/manifest.json"];
  
  for (const file of builtFiles) {
    if (fs.existsSync(file)) {
      const stats = fs.statSync(file);
      console.log(`✅ ${file} (${stats.size} bytes)`);
    } else {
      throw new Error(`Missing built file: ${file}`);
    }
  }

  // Step 7: Check updates.xml files
  console.log("\n📝 Checking update files...");
  const updateFiles = ["updates.xml", "updates-beta.xml"];
  
  for (const file of updateFiles) {
    if (fs.existsSync(file)) {
      console.log(`✅ ${file}`);
    } else {
      console.warn(`⚠️  ${file} not found`);
    }
  }

  // Step 8: Simulate meta.json creation
  console.log("\n📋 Creating meta.json...");
  const datedir = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const meta = {
    mobiusdaemon_crx_url: `https://chrome-beta.mobiusmdm.com/archive/${datedir}/mobiusdaemon.crx`,
    updates_xml: `https://chrome-beta.mobiusmdm.com/archive/${datedir}/updates.xml`,
    version: datedir
  };
  
  fs.writeFileSync("meta.json", JSON.stringify(meta, null, 2));
  console.log("✅ meta.json created");

  // Step 9: Final verification
  console.log("\n✅ All steps completed successfully!");
  console.log("🎉 Chrome extension is ready for deployment!");
  
} catch (error) {
  console.error("\n❌ Deployment demo failed:", error.message);
  process.exit(1);
}
