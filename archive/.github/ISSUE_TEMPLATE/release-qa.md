---
name: Release QA
about: Quality assurance checklist for Mobius releases
title: 'Release QA: '
labels: ['release', 'qa', '#g-mdm', '#g-software', '#g-orchestration', '~engineering-initiated']
assignees: ['pezhub', 'jmwatts', 'xpkoala']
---

# Release QA Checklist

## Release Information
**Version:** 
**Release Branch:** 
**Target Date:** 
**Release Manager:** 

## Pre-Release Testing

### Core Functionality
- [ ] Device enrollment (macOS, Windows, Linux, iOS, Android)
- [ ] Device commands execution
- [ ] Policy creation and assignment
- [ ] Application management
- [ ] License management
- [ ] User authentication and authorization

### API Testing
- [ ] All documented API endpoints respond correctly
- [ ] Authentication mechanisms work properly
- [ ] Rate limiting functions as expected
- [ ] API documentation is up to date

### Web Interface Testing
- [ ] Login/logout functionality
- [ ] Device management interface
- [ ] Policy management interface
- [ ] Application management interface
- [ ] User management interface
- [ ] Dashboard and reporting features

### CLI Testing
- [ ] All CLI commands function properly
- [ ] Configuration management works
- [ ] Authentication with server successful
- [ ] Command completion and help system

### Security Testing
- [ ] JWT authentication working
- [ ] Input validation on all endpoints
- [ ] SQL injection protection verified
- [ ] XSS protection verified
- [ ] TLS/SSL configuration correct

### Performance Testing
- [ ] Load testing completed
- [ ] Memory usage within acceptable limits
- [ ] Database performance acceptable
- [ ] API response times meet SLA

### Platform-Specific Testing

#### macOS
- [ ] MDM enrollment works
- [ ] Configuration profiles apply correctly
- [ ] Application installation/removal
- [ ] System commands execute properly

#### Windows
- [ ] MDM enrollment works
- [ ] Configuration policies apply correctly
- [ ] Application management functions
- [ ] System commands execute properly

#### Linux
- [ ] Agent installation successful
- [ ] OSQuery integration working
- [ ] Command execution functional
- [ ] Application management working

#### Mobile (iOS/Android)
- [ ] Device enrollment successful
- [ ] Profile management working
- [ ] Application management functional
- [ ] Remote commands working

### Integration Testing
- [ ] OSQuery data collection
- [ ] Vulnerability scanning
- [ ] Third-party integrations (if any)
- [ ] Logging and monitoring systems

## Documentation
- [ ] Release notes completed
- [ ] API documentation updated
- [ ] User guides updated
- [ ] Installation instructions verified
- [ ] Migration guides (if applicable)

## Deployment
- [ ] Docker images built and tested
- [ ] Deployment scripts tested
- [ ] Database migrations tested
- [ ] Rollback procedures verified

## Post-Release
- [ ] Monitoring dashboards functional
- [ ] Error tracking operational
- [ ] Support documentation updated
- [ ] Team notifications sent

## Issues Found
List any issues discovered during QA:

## Sign-off
- [ ] **Engineering Team Lead** - @pezhub
- [ ] **Software Team Lead** - @jmwatts  
- [ ] **Orchestration Team Lead** - @xpkoala

## Additional Notes
Any additional context, concerns, or observations: