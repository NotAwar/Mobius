#!/usr/bin/env node

/**
 * Test service to verify Chrome extension functionality
 */

const fs = require('fs');
const path = require('path');

function testService() {
    console.log('🔧 Testing Mobius Chrome Extension Service...');
    
    // Check if required files exist
    const requiredFiles = [
        'manifest.json',
        'package.json',
        'dist/background.js',
        'dist/content.js',
        'dist/popup.html',
        'dist/manifest.json'
    ];
    
    let allFilesExist = true;
    
    for (const file of requiredFiles) {
        const filePath = path.join(__dirname, file);
        if (!fs.existsSync(filePath)) {
            console.error(`❌ Missing required file: ${file}`);
            allFilesExist = false;
        } else {
            console.log(`✅ Found: ${file}`);
        }
    }
    
    // Check if manifest.json is valid
    try {
        const manifestPath = path.join(__dirname, 'manifest.json');
        const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
        
        console.log(`✅ Manifest version: ${manifest.version}`);
        console.log(`✅ Extension name: ${manifest.name}`);
        
        // Check if required manifest fields exist
        const requiredManifestFields = ['name', 'version', 'manifest_version', 'background', 'content_scripts'];
        for (const field of requiredManifestFields) {
            if (!manifest[field]) {
                console.error(`❌ Missing required manifest field: ${field}`);
                allFilesExist = false;
            } else {
                console.log(`✅ Manifest field present: ${field}`);
            }
        }
        
    } catch (error) {
        console.error(`❌ Invalid manifest.json: ${error.message}`);
        allFilesExist = false;
    }
    
    // Check if package.json is valid
    try {
        const packagePath = path.join(__dirname, 'package.json');
        const pkg = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
        
        console.log(`✅ Package name: ${pkg.name}`);
        console.log(`✅ Package version: ${pkg.version}`);
        
        // Check if required scripts exist
        const requiredScripts = ['build', 'test'];
        for (const script of requiredScripts) {
            if (!pkg.scripts || !pkg.scripts[script]) {
                console.error(`❌ Missing required script: ${script}`);
                allFilesExist = false;
            } else {
                console.log(`✅ Script present: ${script}`);
            }
        }
        
    } catch (error) {
        console.error(`❌ Invalid package.json: ${error.message}`);
        allFilesExist = false;
    }
    
    // Check if built files are newer than source files
    const sourceFiles = [
        'src/background.js',
        'src/content.js',
        'src/popup.html'
    ];
    
    const builtFiles = [
        'dist/background.js',
        'dist/content.js',
        'dist/popup.html'
    ];
    
    for (let i = 0; i < sourceFiles.length; i++) {
        const sourcePath = path.join(__dirname, sourceFiles[i]);
        const builtPath = path.join(__dirname, builtFiles[i]);
        
        if (fs.existsSync(sourcePath) && fs.existsSync(builtPath)) {
            const sourceStats = fs.statSync(sourcePath);
            const builtStats = fs.statSync(builtPath);
            
            if (builtStats.mtime >= sourceStats.mtime) {
                console.log(`✅ Built file is up to date: ${builtFiles[i]}`);
            } else {
                console.warn(`⚠️  Built file may be outdated: ${builtFiles[i]}`);
            }
        }
    }
    
    if (allFilesExist) {
        console.log('\n🎉 Chrome extension service test passed!');
        console.log('✅ All required files are present and valid');
        console.log('✅ Extension is ready for deployment');
        return true;
    } else {
        console.log('\n❌ Chrome extension service test failed!');
        console.log('❌ Some required files are missing or invalid');
        return false;
    }
}

// Run the test
if (require.main === module) {
    const success = testService();
    process.exit(success ? 0 : 1);
}

module.exports = testService;
