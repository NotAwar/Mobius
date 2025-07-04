module.exports = {


  friendlyName: 'Send aggregated metrics to datadog',


  description: 'Sends the aggregated metrics for usage statistics reported by Mobius instances in the past week',


  fn: async function () {

    sails.log('Running custom shell script... (`sails run send-metrics-to-datadog`)');

    let nowAt = Date.now();
    let oneWeekAgoAt = nowAt - (1000 * 60 * 60 * 24 * 7);
    // get a timestamp in seconds to use for the metrics we'll send to datadog.
    let timestampForTheseMetrics = Math.floor(nowAt / 1000);
    // Get all the usage snapshots for the past week.
    let usageStatisticsReportedInTheLastWeek = await HistoricalUsageSnapshot.find({
      createdAt: { '>=': oneWeekAgoAt},// Search for records created in the past week.
    })
    .sort('createdAt DESC');// Sort the results by the createdAt timestamp
    // Filter out development premium licenses and loadtests.
    let filteredStatistics = _.filter(usageStatisticsReportedInTheLastWeek, (report)=>{
      return !_.contains(['Mobius Sandbox', 'mobius-loadtest', 'development-only', 'Dev license (expired)', ''], report.organization);
    });

    let statisticsReportedByMobiusInstance = _.groupBy(filteredStatistics, 'anonymousIdentifier');

    let metricsToReport = [];
    let latestStatisticsForEachInstance = [];
    for (let id in statisticsReportedByMobiusInstance) {
      let lastReportIdForThisInstance = _.max(_.pluck(statisticsReportedByMobiusInstance[id], 'id'));
      let latestReportFromThisInstance = _.find(statisticsReportedByMobiusInstance[id], {id: lastReportIdForThisInstance});
      latestStatisticsForEachInstance.push(latestReportFromThisInstance);
    }
    // Get a filtered array of metrics reported by Mobius Premium instances
    let latestPremiumUsageStatistics = _.filter(latestStatisticsForEachInstance, {licenseTier: 'premium'});
    // Group reports by organization name.
    let reportsByOrgName = _.groupBy(latestPremiumUsageStatistics, 'organization');
    for(let org in reportsByOrgName) {
      // Sort the results for this array by the createdAt value. This makes sure we're always sending the most recent results.
      let reportsForThisOrg = _.sortByOrder(reportsByOrgName[org], 'createdAt', 'desc');
      let lastReportForThisOrg = reportsForThisOrg[0];
      // Get the metrics we'll report for each org.
      // Combine the numHostsEnrolled values from the last report for each unique Mobius instance that reports this organization.
      let totalNumberOfHostsReportedByThisOrg = _.sum(reportsForThisOrg, (report)=>{
        return report.numHostsEnrolled;
      });
      let lastReportedMobiusVersion = lastReportForThisOrg.mobiusVersion;
      let hostCountMetricForThisOrg = {
        metric: 'usage_statistics.num_hosts_enrolled_by_org',
        type: 3,
        points: [{
          timestamp: timestampForTheseMetrics,
          value: totalNumberOfHostsReportedByThisOrg
        }],
        resources: [{
          name: reportsByOrgName[org][0].anonymousIdentifier,
          type: 'mobius_instance'
        }],
        tags: [
          `organization:${org}`,
          `mobius_version:${lastReportedMobiusVersion}`,
        ],
      };
      metricsToReport.push(hostCountMetricForThisOrg);
    }
    // Filter the statistics to be only for released versions of Mobius.
    // Note: we're doing this after we've reported the metrics for Mobius Premium instances to make sure
    // that we are reporting metrics sent by customers who may be using a non-4.x.x version of Mobius.
    let latestStatisticsReportedByReleasedMobiusVersions = _.filter(latestStatisticsForEachInstance, (statistics)=>{
      return _.startsWith(statistics.mobiusVersion, '4.');
    });
    let numberOfInstancesToReport = latestStatisticsReportedByReleasedMobiusVersions.length;


    //
    //       ██╗███████╗ ██████╗ ███╗   ██╗    ███╗   ███╗███████╗████████╗██████╗ ██╗ ██████╗███████╗
    //       ██║██╔════╝██╔═══██╗████╗  ██║    ████╗ ████║██╔════╝╚══██╔══╝██╔══██╗██║██╔════╝██╔════╝
    //       ██║███████╗██║   ██║██╔██╗ ██║    ██╔████╔██║█████╗     ██║   ██████╔╝██║██║     ███████╗
    //  ██   ██║╚════██║██║   ██║██║╚██╗██║    ██║╚██╔╝██║██╔══╝     ██║   ██╔══██╗██║██║     ╚════██║
    //  ╚█████╔╝███████║╚██████╔╝██║ ╚████║    ██║ ╚═╝ ██║███████╗   ██║   ██║  ██║██║╚██████╗███████║
    //   ╚════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝    ╚═╝     ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝ ╚═════╝╚══════╝
    //
    // Create an empty object to store combined host counts.
    let combinedHostsEnrolledByOperatingSystem = {};
    // Get an array of the last reported hostsEnrolledByOperatingSystem values.
    let allHostsEnrolledByOsValues = _.pluck(latestStatisticsReportedByReleasedMobiusVersions, 'hostsEnrolledByOperatingSystem');
    // Iterate through each reported value, and combine them.
    for(let reportedHostCounts of allHostsEnrolledByOsValues) {
      _.merge(combinedHostsEnrolledByOperatingSystem, reportedHostCounts, (combinedCountsForThisOperatingSystemType, countsForThisOperatingSystemType) => {
        if(Array.isArray(combinedCountsForThisOperatingSystemType) && Array.isArray(countsForThisOperatingSystemType)){
          let mergedArrayOfHostCounts = [];
          // Iterate through the counts in the array we're combining with the aggregator object.
          for (let versionInfo of countsForThisOperatingSystemType) {
            let matchingVersionFromCombinedCounts = _.find(combinedCountsForThisOperatingSystemType, (osType) => osType.version === versionInfo.version);
            if (matchingVersionFromCombinedCounts) {
              mergedArrayOfHostCounts.push({ version: versionInfo.version, numEnrolled: versionInfo.numEnrolled + matchingVersionFromCombinedCounts.numEnrolled });
            } else {
              mergedArrayOfHostCounts.push(versionInfo);
            }
          }
          // Now add the hostCounts from the combined host counts.
          for (let versionInfo of combinedCountsForThisOperatingSystemType) {
            let versionOnlyExistsInCombinedCounts = !_.find(countsForThisOperatingSystemType, (osVersion)=>{ return osVersion.version === versionInfo.version;});
            if (versionOnlyExistsInCombinedCounts) {
              mergedArrayOfHostCounts.push(versionInfo);
            }
          }
          return mergedArrayOfHostCounts;
        }
      });
    }
    for(let operatingSystem in combinedHostsEnrolledByOperatingSystem) {
      // For every object in the array, we'll send a metric to track host count for each operating system version.
      for(let osVersion of combinedHostsEnrolledByOperatingSystem[operatingSystem]) {
        // Only continue if the object in the array has a numEnrolled and version value.
        if(osVersion.numEnrolled && osVersion.version !== '') {
          let metricToAdd = {
            metric: 'usage_statistics_v2.host_count_by_os_version',
            type: 3,
            points: [{timestamp: timestampForTheseMetrics, value:osVersion.numEnrolled}],
            resources: [{name: operatingSystem, type: 'os_type'}],
            tags: [`os_version_name:${osVersion.version}`],
          };
          // Add the custom metric to the array of metrics to send to Datadog.
          metricsToReport.push(metricToAdd);
        }//ﬁ
      }//∞
    }//∞


    let allHostsEnrolledByOsqueryVersion = _.pluck(latestStatisticsReportedByReleasedMobiusVersions, 'hostsEnrolledByOsqueryVersion');
    let combinedHostsEnrolledByOsqueryVersion = [];
    let flattenedHostsEnrolledByOsqueryVersions = _.flatten(allHostsEnrolledByOsqueryVersion);
    let groupedHostsEnrolledValuesByOsqueryVersion = _.groupBy(flattenedHostsEnrolledByOsqueryVersions, 'osqueryVersion');
    for(let osqueryVersion in groupedHostsEnrolledValuesByOsqueryVersion) {
      combinedHostsEnrolledByOsqueryVersion.push({
        osqueryVersion: osqueryVersion,
        numHosts: _.sum(groupedHostsEnrolledValuesByOsqueryVersion[osqueryVersion], (version)=>{return version.numHosts;})
      });
    }

    for(let version of combinedHostsEnrolledByOsqueryVersion) {
      if(version.osqueryVersion !== ''){
        let metricToAdd = {
          metric: 'usage_statistics_v2.host_count_by_osquery_version',
          type: 3,
          points: [{timestamp: timestampForTheseMetrics, value:version.numHosts}],
          tags: [`osquery_version:${version.osqueryVersion}`],
        };
        // Add the custom metric to the array of metrics to send to Datadog.
        metricsToReport.push(metricToAdd);
      }
    }//∞


    let combinedHostsEnrolledByOrbitVersion = [];
    let allHostsEnrolledByOrbitVersion = _.pluck(latestStatisticsReportedByReleasedMobiusVersions, 'hostsEnrolledByOrbitVersion');
    let flattenedHostsEnrolledByOrbitVersions = _.flatten(allHostsEnrolledByOrbitVersion);
    let groupedHostsEnrolledValuesByOrbitVersion = _.groupBy(flattenedHostsEnrolledByOrbitVersions, 'orbitVersion');
    for(let orbitVersion in groupedHostsEnrolledValuesByOrbitVersion) {
      combinedHostsEnrolledByOrbitVersion.push({
        orbitVersion: orbitVersion,
        numHosts: _.sum(groupedHostsEnrolledValuesByOrbitVersion[orbitVersion], (version)=>{return version.numHosts;})
      });
    }
    for(let version of combinedHostsEnrolledByOrbitVersion) {
      if(version.orbitVersion !== '') {
        let metricToAdd = {
          metric: 'usage_statistics_v2.host_count_by_orbit_version',
          type: 3,
          points: [{timestamp: timestampForTheseMetrics, value:version.numHosts}],
          tags: [`orbit_version:${version.orbitVersion}`],
        };
        // Add the custom metric to the array of metrics to send to Datadog.
        metricsToReport.push(metricToAdd);
      }
    }//∞

    // Merge the arrays of JSON storedErrors
    let allStoredErrors = _.pluck(latestStatisticsReportedByReleasedMobiusVersions, 'storedErrors');
    let flattenedStoredErrors = _.flatten(allStoredErrors);
    let groupedStoredErrorsByLocation = _.groupBy(flattenedStoredErrors, 'loc');
    let combinedStoredErrors = [];
    for(let location in groupedStoredErrorsByLocation) {
      combinedStoredErrors.push({
        location: groupedStoredErrorsByLocation[location][0].loc,
        count: _.sum(groupedStoredErrorsByLocation[location], (location)=>{return location.count;}),
        numberOfInstancesReportingThisError: groupedStoredErrorsByLocation[location].length
      });
    }
    for(let error of combinedStoredErrors) {
      // Create a new array of tags for this error
      let errorTags = [];
      let errorLocation = 1;
      // Create a tag for each error location
      for(let location of error.location) { // iterate throught the location array of this error
        // Add the error's location as a custom tag (SNAKE_CASED)
        errorTags.push(`error_location_${errorLocation}:${location.replace(/\s/gi, '_')}`);
        errorLocation++;
      }
      // Add a metric with the combined error count for each unique error location
      metricsToReport.push({
        metric: 'usage_statistics_v2.stored_errors_counts',
        type: 3,
        points: [{timestamp: timestampForTheseMetrics, value: error.count}],
        tags: errorTags,
      });
      // Add a metric to report how many different instances reported errors with the same location.
      metricsToReport.push({
        metric: 'usage_statistics_v2.stored_errors_statistics',
        type: 3,
        points: [{timestamp: timestampForTheseMetrics, value: error.numberOfInstancesReportingThisError}],
        tags: errorTags,
      });
    }//∞

    //
    //  ███████╗████████╗██████╗ ██╗███╗   ██╗ ██████╗
    //  ██╔════╝╚══██╔══╝██╔══██╗██║████╗  ██║██╔════╝
    //  ███████╗   ██║   ██████╔╝██║██╔██╗ ██║██║  ███╗
    //  ╚════██║   ██║   ██╔══██╗██║██║╚██╗██║██║   ██║
    //  ███████║   ██║   ██║  ██║██║██║ ╚████║╚██████╔╝
    //  ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝
    //
    //  ███╗   ███╗███████╗████████╗██████╗ ██╗ ██████╗███████╗
    //  ████╗ ████║██╔════╝╚══██╔══╝██╔══██╗██║██╔════╝██╔════╝
    //  ██╔████╔██║█████╗     ██║   ██████╔╝██║██║     ███████╗
    //  ██║╚██╔╝██║██╔══╝     ██║   ██╔══██╗██║██║     ╚════██║
    //  ██║ ╚═╝ ██║███████╗   ██║   ██║  ██║██║╚██████╗███████║
    //  ╚═╝     ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝ ╚═════╝╚══════╝
    //
    // Build a metric for each Mobius version reported.
    let statisticsByReportedMobiusVersion = _.groupBy(latestStatisticsReportedByReleasedMobiusVersions, 'mobiusVersion');
    for(let version in statisticsByReportedMobiusVersion){
      let numberOfInstancesReportingThisVersion = statisticsByReportedMobiusVersion[version].length;
      metricsToReport.push({
        metric: 'usage_statistics.mobius_version',
        type: 3,
        points: [{
          timestamp: timestampForTheseMetrics,
          value: numberOfInstancesReportingThisVersion
        }],
        tags: [`mobius_version:${version}`],
      });
    }
    // Build a metric for each license tier reported.
    let statisticsByReportedMobiusLicenseTier = _.groupBy(latestStatisticsReportedByReleasedMobiusVersions, 'licenseTier');
    for(let tier in statisticsByReportedMobiusLicenseTier){
      let numberOfInstancesReportingThisLicenseTier = statisticsByReportedMobiusLicenseTier[tier].length;
      metricsToReport.push({
        metric: 'usage_statistics.mobius_license',
        type: 3,
        points: [{
          timestamp: timestampForTheseMetrics,
          value: numberOfInstancesReportingThisLicenseTier
        }],
        tags: [`license_tier:${tier}`],
      });
    }


    //
    //  ██████╗  ██████╗  ██████╗ ██╗     ███████╗ █████╗ ███╗   ██╗
    //  ██╔══██╗██╔═══██╗██╔═══██╗██║     ██╔════╝██╔══██╗████╗  ██║
    //  ██████╔╝██║   ██║██║   ██║██║     █████╗  ███████║██╔██╗ ██║
    //  ██╔══██╗██║   ██║██║   ██║██║     ██╔══╝  ██╔══██║██║╚██╗██║
    //  ██████╔╝╚██████╔╝╚██████╔╝███████╗███████╗██║  ██║██║ ╚████║
    //  ╚═════╝  ╚═════╝  ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝
    //
    //  ███╗   ███╗███████╗████████╗██████╗ ██╗ ██████╗███████╗
    //  ████╗ ████║██╔════╝╚══██╔══╝██╔══██╗██║██╔════╝██╔════╝
    //  ██╔████╔██║█████╗     ██║   ██████╔╝██║██║     ███████╗
    //  ██║╚██╔╝██║██╔══╝     ██║   ██╔══██╗██║██║     ╚════██║
    //  ██║ ╚═╝ ██║███████╗   ██║   ██║  ██║██║╚██████╗███████║
    //  ╚═╝     ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝ ╚═════╝╚══════╝
    //
    // Software Inventory
    let numberOfInstancesWithSoftwareInventoryEnabled = _.where(latestStatisticsReportedByReleasedMobiusVersions, {softwareInventoryEnabled: true}).length;
    let numberOfInstancesWithSoftwareInventoryDisabled = numberOfInstancesToReport - numberOfInstancesWithSoftwareInventoryEnabled;
    metricsToReport.push({
      metric: 'usage_statistics.software_inventory',
      type: 3,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: numberOfInstancesWithSoftwareInventoryEnabled
      }],
      tags: [`enabled:true`],
    });
    metricsToReport.push({
      metric: 'usage_statistics.software_inventory',
      type: 3,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: numberOfInstancesWithSoftwareInventoryDisabled
      }],
      tags: [`enabled:false`],
    });
    // vulnDetectionEnabled
    let numberOfInstancesWithVulnDetectionEnabled = _.where(latestStatisticsReportedByReleasedMobiusVersions, {vulnDetectionEnabled: true}).length;
    let numberOfInstancesWithVulnDetectionDisabled = numberOfInstancesToReport - numberOfInstancesWithVulnDetectionEnabled;
    metricsToReport.push({
      metric: 'usage_statistics.vuln_detection',
      type: 3,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: numberOfInstancesWithVulnDetectionEnabled
      }],
      tags: [`enabled:true`],
    });
    metricsToReport.push({
      metric: 'usage_statistics.vuln_detection',
      type: 3,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: numberOfInstancesWithVulnDetectionDisabled
      }],
      tags: [`enabled:false`],
    });
    // SystemUsersEnabled
    let numberOfInstancesWithSystemUsersEnabled = _.where(latestStatisticsReportedByReleasedMobiusVersions, {systemUsersEnabled: true}).length;
    let numberOfInstancesWithSystemUsersDisabled = numberOfInstancesToReport - numberOfInstancesWithSystemUsersEnabled;
    metricsToReport.push({
      metric: 'usage_statistics.system_users',
      type: 3,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: numberOfInstancesWithSystemUsersEnabled
      }],
      tags: [`enabled:true`],
    });
    metricsToReport.push({
      metric: 'usage_statistics.system_users',
      type: 3,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: numberOfInstancesWithSystemUsersDisabled
      }],
      tags: [`enabled:false`],
    });
    // hostsStatusWebHookEnabled
    let numberOfInstancesWithHostsStatusWebHookEnabled = _.where(latestStatisticsReportedByReleasedMobiusVersions, {hostsStatusWebHookEnabled: true}).length;
    let numberOfInstancesWithHostsStatusWebHookDisabled = numberOfInstancesToReport - numberOfInstancesWithHostsStatusWebHookEnabled;
    metricsToReport.push({
      metric: 'usage_statistics.host_status_webhook',
      type: 3,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: numberOfInstancesWithHostsStatusWebHookEnabled
      }],
      tags: [`enabled:true`],
    });
    metricsToReport.push({
      metric: 'usage_statistics.host_status_webhook',
      type: 3,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: numberOfInstancesWithHostsStatusWebHookDisabled
      }],
      tags: [`enabled:false`],
    });
    // mdmMacOsEnabled
    let numberOfInstancesWithMdmMacOsEnabled = _.where(latestStatisticsReportedByReleasedMobiusVersions, {mdmMacOsEnabled: true}).length;
    let numberOfInstancesWithMdmMacOsDisabled = numberOfInstancesToReport - numberOfInstancesWithMdmMacOsEnabled;
    metricsToReport.push({
      metric: 'usage_statistics.macos_mdm',
      type: 3,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: numberOfInstancesWithMdmMacOsEnabled
      }],
      tags: [`enabled:true`],
    });
    metricsToReport.push({
      metric: 'usage_statistics.macos_mdm',
      type: 3,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: numberOfInstancesWithMdmMacOsDisabled
      }],
      tags: [`enabled:false`],
    });
    // mdmWindowsEnabled
    let numberOfInstancesWithMdmWindowsEnabled = _.where(latestStatisticsReportedByReleasedMobiusVersions, {mdmWindowsEnabled: true}).length;
    let numberOfInstancesWithMdmWindowsDisabled = numberOfInstancesToReport - numberOfInstancesWithMdmWindowsEnabled;
    metricsToReport.push({
      metric: 'usage_statistics.windows_mdm',
      type: 3,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: numberOfInstancesWithMdmWindowsEnabled
      }],
      tags: [`enabled:true`],
    });
    metricsToReport.push({
      metric: 'usage_statistics.windows_mdm',
      type: 3,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: numberOfInstancesWithMdmWindowsDisabled
      }],
      tags: [`enabled:false`],
    });
    // liveQueryDisabled
    let numberOfInstancesWithLiveQueryDisabled = _.where(latestStatisticsReportedByReleasedMobiusVersions, {liveQueryDisabled: true}).length;
    let numberOfInstancesWithLiveQueryEnabled = numberOfInstancesToReport - numberOfInstancesWithLiveQueryDisabled;
    metricsToReport.push({
      metric: 'usage_statistics.live_query',
      type: 3,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: numberOfInstancesWithLiveQueryDisabled
      }],
      tags: [`enabled:false`],
    });
    metricsToReport.push({
      metric: 'usage_statistics.live_query',
      type: 3,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: numberOfInstancesWithLiveQueryEnabled
      }],
      tags: [`enabled:true`],
    });
    // hostExpiryEnabled
    let numberOfInstancesWithHostExpiryEnabled = _.where(latestStatisticsReportedByReleasedMobiusVersions, {hostExpiryEnabled: true}).length;
    let numberOfInstancesWithHostExpiryDisabled = numberOfInstancesToReport - numberOfInstancesWithHostExpiryEnabled;
    metricsToReport.push({
      metric: 'usage_statistics.host_expiry',
      type: 3,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: numberOfInstancesWithHostExpiryEnabled
      }],
      tags: [`enabled:true`],
    });
    metricsToReport.push({
      metric: 'usage_statistics.host_expiry',
      type: 3,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: numberOfInstancesWithHostExpiryDisabled
      }],
      tags: [`enabled:false`],
    });
    // aiFeaturesDisabled
    let numberOfInstancesWithAiFeaturesDisabled = _.where(latestStatisticsReportedByReleasedMobiusVersions, {aiFeaturesDisabled: true}).length;
    let numberOfInstancesWithAiFeaturesEnabled = numberOfInstancesToReport - numberOfInstancesWithAiFeaturesDisabled;
    metricsToReport.push({
      metric: 'usage_statistics.ai_features',
      type: 3,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: numberOfInstancesWithAiFeaturesEnabled
      }],
      tags: [`enabled:true`],
    });
    metricsToReport.push({
      metric: 'usage_statistics.ai_features',
      type: 3,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: numberOfInstancesWithAiFeaturesDisabled
      }],
      tags: [`enabled:false`],
    });
    // maintenanceWindowsEnabled
    let numberOfInstancesWithMaintenanceWindowsEnabled = _.where(latestStatisticsReportedByReleasedMobiusVersions, {maintenanceWindowsEnabled: true}).length;
    let numberOfInstancesWithMaintenanceWindowsDisabled = numberOfInstancesToReport - numberOfInstancesWithMaintenanceWindowsEnabled;
    metricsToReport.push({
      metric: 'usage_statistics.maintenance_windows',
      type: 3,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: numberOfInstancesWithMaintenanceWindowsEnabled
      }],
      tags: [`enabled:true`],
    });
    metricsToReport.push({
      metric: 'usage_statistics.maintenance_windows',
      type: 3,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: numberOfInstancesWithMaintenanceWindowsDisabled
      }],
      tags: [`enabled:false`],
    });
    // maintenanceWindowsConfigured
    let numberOfInstancesWithMaintenanceWindowsConfigured = _.where(latestStatisticsReportedByReleasedMobiusVersions, {maintenanceWindowsEnabled: true}).length;
    let numberOfInstancesWithoutMaintenanceWindowsConfigured = numberOfInstancesToReport - numberOfInstancesWithMaintenanceWindowsConfigured;
    metricsToReport.push({
      metric: 'usage_statistics.maintenance_windows_configured',
      type: 3,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: numberOfInstancesWithMaintenanceWindowsConfigured
      }],
      tags: [`configured:true`],
    });
    metricsToReport.push({
      metric: 'usage_statistics.maintenance_windows_configured',
      type: 3,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: numberOfInstancesWithoutMaintenanceWindowsConfigured
      }],
      tags: [`configured:false`],
    });


    //
    //  ███╗   ██╗██╗   ██╗███╗   ███╗██████╗ ███████╗██████╗
    //  ████╗  ██║██║   ██║████╗ ████║██╔══██╗██╔════╝██╔══██╗
    //  ██╔██╗ ██║██║   ██║██╔████╔██║██████╔╝█████╗  ██████╔╝
    //  ██║╚██╗██║██║   ██║██║╚██╔╝██║██╔══██╗██╔══╝  ██╔══██╗
    //  ██║ ╚████║╚██████╔╝██║ ╚═╝ ██║██████╔╝███████╗██║  ██║
    //  ╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝
    //
    //  ███╗   ███╗███████╗████████╗██████╗ ██╗ ██████╗███████╗
    //  ████╗ ████║██╔════╝╚══██╔══╝██╔══██╗██║██╔════╝██╔════╝
    //  ██╔████╔██║█████╗     ██║   ██████╔╝██║██║     ███████╗
    //  ██║╚██╔╝██║██╔══╝     ██║   ██╔══██╗██║██║     ╚════██║
    //  ██║ ╚═╝ ██║███████╗   ██║   ██║  ██║██║╚██████╗███████║
    //  ╚═╝     ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝ ╚═════╝╚══════╝
    //
    // Create two metrics to track total number of hosts reported in the last week.
    let totalNumberOfHostsReportedByPremiumInstancesInTheLastWeek = _.sum(_.pluck(_.filter(latestStatisticsReportedByReleasedMobiusVersions, {licenseTier: 'premium'}), 'numHostsEnrolled'));
    metricsToReport.push({
      metric: 'usage_statistics.total_num_hosts_enrolled',
      type: 3,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: totalNumberOfHostsReportedByPremiumInstancesInTheLastWeek
      }],
      tags: [`license_tier:premium`],
    });

    let totalNumberOfHostsReportedByFreeInstancesInTheLastWeek = _.sum(_.pluck(_.filter(latestStatisticsReportedByReleasedMobiusVersions, {licenseTier: 'free'}), 'numHostsEnrolled'));
    metricsToReport.push({
      metric: 'usage_statistics.total_num_hosts_enrolled',
      type: 3,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: totalNumberOfHostsReportedByFreeInstancesInTheLastWeek
      }],
      tags: [`license_tier:free`],
    });

    // numUsers
    let mobiusInstancesThatReportedNumUsers = _.filter(latestStatisticsReportedByReleasedMobiusVersions, (statistics)=>{
      return statistics.numUsers > 0;
    });

    let averageNumberOfUsers = Math.floor(_.sum(_.pluck(mobiusInstancesThatReportedNumUsers, 'numUsers')) / mobiusInstancesThatReportedNumUsers.length);
    metricsToReport.push({
      metric: 'usage_statistics.avg_num_users',
      type: 1,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: averageNumberOfUsers
      }],
    });

    let highestNumberOfUsers = _.max(_.pluck(mobiusInstancesThatReportedNumUsers, 'numUsers'));
    metricsToReport.push({
      metric: 'usage_statistics.max_num_users',
      type: 1,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: highestNumberOfUsers
      }],
    });

    // numTeams
    let mobiusInstancesThatReportedNumTeams = _.filter(latestStatisticsReportedByReleasedMobiusVersions, (statistics)=>{
      return statistics.numTeams > 0;
    });

    let averageNumberOfTeams = Math.floor(_.sum(_.pluck(mobiusInstancesThatReportedNumTeams, 'numTeams')) / mobiusInstancesThatReportedNumTeams.length);
    metricsToReport.push({
      metric: 'usage_statistics.avg_num_teams',
      type: 1,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: averageNumberOfTeams
      }],
    });

    let highestNumberOfTeams = _.max(_.pluck(mobiusInstancesThatReportedNumTeams, 'numTeams'));
    metricsToReport.push({
      metric: 'usage_statistics.max_num_teams',
      type: 1,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: highestNumberOfTeams
      }],
    });

    // numPolicies
    let mobiusInstancesThatReportedNumPolicies = _.filter(latestStatisticsReportedByReleasedMobiusVersions, (statistics)=>{
      return statistics.numPolicies > 0;
    });

    let averageNumberOfPolicies = Math.floor(_.sum(_.pluck(mobiusInstancesThatReportedNumPolicies, 'numPolicies')) / mobiusInstancesThatReportedNumPolicies.length);
    metricsToReport.push({
      metric: 'usage_statistics.avg_num_policies',
      type: 1,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: averageNumberOfPolicies
      }],
    });

    let highestNumberOfPolicies = _.max(_.pluck(mobiusInstancesThatReportedNumPolicies, 'numPolicies'));
    metricsToReport.push({
      metric: 'usage_statistics.max_num_policies',
      type: 1,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: highestNumberOfPolicies
      }],
    });

    // numLabels
    let mobiusInstancesThatReportedNumLabels = _.filter(latestStatisticsReportedByReleasedMobiusVersions, (statistics)=>{
      return statistics.numLabels > 0;
    });

    let averageNumberOfLabels = Math.floor(_.sum(_.pluck(mobiusInstancesThatReportedNumLabels, 'numLabels')) / mobiusInstancesThatReportedNumLabels.length);
    metricsToReport.push({
      metric: 'usage_statistics.avg_num_labels',
      type: 1,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: averageNumberOfLabels
      }],
    });

    let highestNumberOfLabels = _.max(_.pluck(mobiusInstancesThatReportedNumLabels, 'numLabels'));
    metricsToReport.push({
      metric: 'usage_statistics.max_num_labels',
      type: 1,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: highestNumberOfLabels
      }],
    });

    // numWeeklyActiveUsers
    let mobiusInstancesThatReportedNumWeeklyActiveUsers = _.filter(latestStatisticsReportedByReleasedMobiusVersions, (statistics)=>{
      return statistics.numWeeklyActiveUsers > 0;
    });

    let averageNumberOfWeeklyActiveUsers = Math.floor(_.sum(_.pluck(mobiusInstancesThatReportedNumWeeklyActiveUsers, 'numWeeklyActiveUsers')) / mobiusInstancesThatReportedNumWeeklyActiveUsers.length);
    metricsToReport.push({
      metric: 'usage_statistics.avg_num_weekly_active_users',
      type: 1,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: averageNumberOfWeeklyActiveUsers
      }],
    });

    let highestNumberOfWeeklyActiveUsers = _.max(_.pluck(mobiusInstancesThatReportedNumWeeklyActiveUsers, 'numWeeklyActiveUsers'));
    metricsToReport.push({
      metric: 'usage_statistics.max_num_weekly_active_users',
      type: 1,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: highestNumberOfWeeklyActiveUsers
      }],
    });

    // numWeeklyPolicyViolationDaysActual
    let mobiusInstancesThatReportedNumWeeklyPolicyViolationDaysActual = _.filter(latestStatisticsReportedByReleasedMobiusVersions, (statistics)=>{
      return statistics.numWeeklyPolicyViolationDaysActual > 0;
    });

    let averageNumberOfWeeklyPolicyViolationDaysActual = Math.floor(_.sum(_.pluck(mobiusInstancesThatReportedNumWeeklyPolicyViolationDaysActual, 'numWeeklyPolicyViolationDaysActual')) / mobiusInstancesThatReportedNumWeeklyPolicyViolationDaysActual.length);
    metricsToReport.push({
      metric: 'usage_statistics.avg_num_weekly_policy_violation_days_actual',
      type: 1,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: averageNumberOfWeeklyPolicyViolationDaysActual
      }],
    });

    let highestNumberOfWeeklyPolicyViolationDaysActual = _.max(_.pluck(mobiusInstancesThatReportedNumWeeklyPolicyViolationDaysActual, 'numWeeklyPolicyViolationDaysActual'));
    metricsToReport.push({
      metric: 'usage_statistics.max_num_weekly_policy_violation_days_actual',
      type: 1,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: highestNumberOfWeeklyPolicyViolationDaysActual
      }],
    });


    // numWeeklyPolicyViolationDaysPossible
    let mobiusInstancesThatReportedNumWeeklyPolicyViolationDaysPossible = _.filter(latestStatisticsReportedByReleasedMobiusVersions, (statistics)=>{
      return statistics.numWeeklyPolicyViolationDaysPossible > 0;
    });

    let averageNumberOfWeeklyPolicyViolationDaysPossible = Math.floor(_.sum(_.pluck(mobiusInstancesThatReportedNumWeeklyPolicyViolationDaysPossible, 'numWeeklyPolicyViolationDaysPossible')) / mobiusInstancesThatReportedNumWeeklyPolicyViolationDaysPossible.length);
    metricsToReport.push({
      metric: 'usage_statistics.avg_num_weekly_policy_violation_days_possible',
      type: 1,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: averageNumberOfWeeklyPolicyViolationDaysPossible
      }],
    });

    let highestNumberOfWeeklyPolicyViolationDaysPossible = _.max(_.pluck(mobiusInstancesThatReportedNumWeeklyPolicyViolationDaysPossible, 'numWeeklyPolicyViolationDaysPossible'));
    metricsToReport.push({
      metric: 'usage_statistics.max_num_weekly_policy_violation_days_possible',
      type: 1,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: highestNumberOfWeeklyPolicyViolationDaysPossible
      }],
    });

    // numHostsNotResponding
    let mobiusInstancesThatReportedNumHostsNotResponding = _.filter(latestStatisticsReportedByReleasedMobiusVersions, (statistics)=>{
      return statistics.numHostsNotResponding > 0;
    });

    let averageNumberOfHostsNotResponding = Math.floor(_.sum(_.pluck(mobiusInstancesThatReportedNumHostsNotResponding, 'numHostsNotResponding')) / mobiusInstancesThatReportedNumHostsNotResponding.length);
    metricsToReport.push({
      metric: 'usage_statistics.avg_num_hosts_not_responding',
      type: 1,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: averageNumberOfHostsNotResponding
      }],
    });

    let highestNumberOfHostsNotResponding = _.max(_.pluck(mobiusInstancesThatReportedNumHostsNotResponding, 'numHostsNotResponding'));
    metricsToReport.push({
      metric: 'usage_statistics.max_num_hosts_not_responding',
      type: 1,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: highestNumberOfHostsNotResponding
      }],
    });

    // numSoftwareVersions
    let mobiusInstancesThatReportedNumSoftwareVersions = _.filter(latestStatisticsReportedByReleasedMobiusVersions, (statistics)=>{
      return statistics.numSoftwareVersions > 0;
    });

    let averageNumberOfSoftwareVersions = Math.floor(_.sum(_.pluck(mobiusInstancesThatReportedNumSoftwareVersions, 'numSoftwareVersions')) / mobiusInstancesThatReportedNumSoftwareVersions.length);
    metricsToReport.push({
      metric: 'usage_statistics.avg_num_software_versions',
      type: 1,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: averageNumberOfSoftwareVersions
      }],
    });

    let highestNumberOfSoftwareVersions = _.max(_.pluck(mobiusInstancesThatReportedNumSoftwareVersions, 'numSoftwareVersions'));
    metricsToReport.push({
      metric: 'usage_statistics.max_num_software_versions',
      type: 1,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: highestNumberOfSoftwareVersions
      }],
    });

    // numHostSoftwares
    let mobiusInstancesThatReportedNumHostSoftware = _.filter(latestStatisticsReportedByReleasedMobiusVersions, (statistics)=>{
      return statistics.numHostSoftwares > 0;
    });

    let averageNumberOfHostSoftware = Math.floor(_.sum(_.pluck(mobiusInstancesThatReportedNumHostSoftware, 'numHostSoftwares')) / mobiusInstancesThatReportedNumHostSoftware.length);
    metricsToReport.push({
      metric: 'usage_statistics.avg_num_host_software',
      type: 1,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: averageNumberOfHostSoftware
      }],
    });

    let highestNumberOfHostSoftware = _.max(_.pluck(mobiusInstancesThatReportedNumHostSoftware, 'numHostSoftwares'));
    metricsToReport.push({
      metric: 'usage_statistics.max_num_host_software',
      type: 1,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: highestNumberOfHostSoftware
      }],
    });


    // numSoftwareTitles
    let mobiusInstancesThatReportedNumSoftwareTitles = _.filter(latestStatisticsReportedByReleasedMobiusVersions, (statistics)=>{
      return statistics.numSoftwareTitles > 0;
    });

    let averageNumberOfSoftwareTitles = Math.floor(_.sum(_.pluck(mobiusInstancesThatReportedNumSoftwareTitles, 'numSoftwareTitles')) / mobiusInstancesThatReportedNumSoftwareTitles.length);
    metricsToReport.push({
      metric: 'usage_statistics.avg_num_software_titles',
      type: 1,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: averageNumberOfSoftwareTitles
      }],
    });

    let highestNumberOfSoftwareTitles = _.max(_.pluck(mobiusInstancesThatReportedNumSoftwareTitles, 'numSoftwareTitles'));
    metricsToReport.push({
      metric: 'usage_statistics.max_num_software_titles',
      type: 1,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: highestNumberOfSoftwareTitles
      }],
    });


    // numHostSoftwareInstalledPaths
    let mobiusInstancesThatReportedNumHostSoftwareInstalledPaths = _.filter(latestStatisticsReportedByReleasedMobiusVersions, (statistics)=>{
      return statistics.numHostSoftwareInstalledPaths > 0;
    });

    let averageNumberOfSoftwareInstalledPaths = Math.floor(_.sum(_.pluck(mobiusInstancesThatReportedNumHostSoftwareInstalledPaths, 'numHostSoftwareInstalledPaths')) / mobiusInstancesThatReportedNumHostSoftwareInstalledPaths.length);
    metricsToReport.push({
      metric: 'usage_statistics.avg_num_software_installed_paths',
      type: 1,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: averageNumberOfSoftwareInstalledPaths
      }],
    });

    let highestNumberOfSoftwareInstalledPaths = _.max(_.pluck(mobiusInstancesThatReportedNumHostSoftwareInstalledPaths, 'numHostSoftwareInstalledPaths'));
    metricsToReport.push({
      metric: 'usage_statistics.max_num_software_installed_paths',
      type: 1,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: highestNumberOfSoftwareInstalledPaths
      }],
    });

    // numSoftwareCPEs
    let mobiusInstancesThatReportedNumSoftwareCPEs = _.filter(latestStatisticsReportedByReleasedMobiusVersions, (statistics)=>{
      return statistics.numSoftwareCPEs > 0;
    });

    let averageNumberOfSoftwareCPEs = Math.floor(_.sum(_.pluck(mobiusInstancesThatReportedNumSoftwareCPEs, 'numSoftwareCPEs')) / mobiusInstancesThatReportedNumSoftwareCPEs.length);
    metricsToReport.push({
      metric: 'usage_statistics.avg_num_software_cpes',
      type: 1,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: averageNumberOfSoftwareCPEs
      }],
    });

    let highestNumberOfSoftwareCPEs = _.max(_.pluck(mobiusInstancesThatReportedNumSoftwareCPEs, 'numSoftwareCPEs'));
    metricsToReport.push({
      metric: 'usage_statistics.max_num_software_cpes',
      type: 1,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: highestNumberOfSoftwareCPEs
      }],
    });


    // numSoftwareCVEs
    let mobiusInstancesThatReportedNumSoftwareCVEs = _.filter(latestStatisticsReportedByReleasedMobiusVersions, (statistics)=>{
      return statistics.numSoftwareCVEs > 0;
    });

    let averageNumberOfSoftwareCVEs = Math.floor(_.sum(_.pluck(mobiusInstancesThatReportedNumSoftwareCVEs, 'numSoftwareCVEs')) / mobiusInstancesThatReportedNumSoftwareCVEs.length);
    metricsToReport.push({
      metric: 'usage_statistics.avg_num_software_cves',
      type: 1,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: averageNumberOfSoftwareCVEs
      }],
    });

    let highestNumberOfSoftwareCVEs = _.max(_.pluck(mobiusInstancesThatReportedNumSoftwareCVEs, 'numSoftwareCVEs'));
    metricsToReport.push({
      metric: 'usage_statistics.max_num_software_cves',
      type: 1,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: highestNumberOfSoftwareCVEs
      }],
    });


    // numHostsMobiusDesktopEnabled
    let mobiusInstancesThatReportedNumHostsMobiusDesktopEnabled = _.filter(latestStatisticsReportedByReleasedMobiusVersions, (statistics)=>{
      return statistics.numHostsMobiusDesktopEnabled > 0;
    });

    let averageNumberOfHostsMobiusDesktopEnabled = Math.floor(_.sum(_.pluck(mobiusInstancesThatReportedNumHostsMobiusDesktopEnabled, 'numHostsMobiusDesktopEnabled')) / mobiusInstancesThatReportedNumHostsMobiusDesktopEnabled.length);
    metricsToReport.push({
      metric: 'usage_statistics.avg_num_hosts_mobius_desktop_enabled',
      type: 1,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: averageNumberOfHostsMobiusDesktopEnabled
      }],
    });

    let highestNumberOfHostsMobiusDesktopEnabled = _.max(_.pluck(mobiusInstancesThatReportedNumHostsMobiusDesktopEnabled, 'numHostsMobiusDesktopEnabled'));
    metricsToReport.push({
      metric: 'usage_statistics.max_num_hosts_mobius_desktop_enabled',
      type: 1,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: highestNumberOfHostsMobiusDesktopEnabled
      }],
    });

    // numQueries
    let mobiusInstancesThatReportedNumQueries = _.filter(latestStatisticsReportedByReleasedMobiusVersions, (statistics)=>{
      return statistics.numQueries > 0;
    });

    let averageNumberOfQueries = Math.floor(_.sum(_.pluck(mobiusInstancesThatReportedNumQueries, 'numQueries')) / mobiusInstancesThatReportedNumQueries.length);
    metricsToReport.push({
      metric: 'usage_statistics.avg_num_queries',
      type: 1,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: averageNumberOfQueries
      }],
    });

    let highestNumberOfQueries = _.max(_.pluck(mobiusInstancesThatReportedNumQueries, 'numQueries'));
    metricsToReport.push({
      metric: 'usage_statistics.max_num_queries',
      type: 1,
      points: [{
        timestamp: timestampForTheseMetrics,
        value: highestNumberOfQueries
      }],
    });


    // Break the metrics into smaller arrays to ensure we don't exceed Datadog's 512 kb request body limit.
    let chunkedMetrics = _.chunk(metricsToReport, 500);// Note: 500 stringified JSON metrics is ~410 kb.
    for(let chunkOfMetrics of chunkedMetrics) {
      await sails.helpers.http.post.with({
        url: 'https://api.us5.datadoghq.com/api/v2/series',
        data: {
          series: chunkOfMetrics,
        },
        headers: {
          'DD-API-KEY': sails.config.custom.datadogApiKey,
          'Content-Type': 'application/json',
        }
      }).intercept((err)=>{
        // If there was an error sending metrics to Datadog, we'll log the error in a warning, but we won't throw an error.
        // This way, we'll still return a 200 status to the Mobius instance that sent usage analytics.
        return new Error(`When the send-metrics-to-datadog script sent a request to send metrics to Datadog, an error occured. Raw error: ${require('util').inspect(err)}`);
      });
    }//∞
    sails.log(`Aggregated metrics for ${numberOfInstancesToReport} Mobius instances from the past week sent to Datadog.`);
  }


};

