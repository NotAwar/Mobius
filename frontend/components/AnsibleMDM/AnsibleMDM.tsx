import React, { useState, useEffect } from 'react';
import { useQuery } from 'react-query';
import { IAnsibleHost, IAnsiblePlaybook } from '../../../interfaces';
import Button from '../../buttons/Button';
import Spinner from '../../Spinner';
import TableContainer from '../../TableContainer';

interface IAnsibleMDMProps {
  onRunPlaybook?: (playbookId: string, hostIds: string[]) => void;
}

const AnsibleMDM: React.FC<IAnsibleMDMProps> = ({ onRunPlaybook }) => {
  const [selectedHosts, setSelectedHosts] = useState<string[]>([]);
  const [selectedPlaybook, setSelectedPlaybook] = useState<string>('');

  const {
    data: hosts,
    isLoading: hostsLoading,
    error: hostsError,
  } = useQuery<IAnsibleHost[]>('ansible-hosts', () =>
    fetch('/api/v1/mobius/ansible/hosts').then((res) => res.json())
  );

  const {
    data: playbooks,
    isLoading: playbooksLoading,
    error: playbooksError,
  } = useQuery<IAnsiblePlaybook[]>('ansible-playbooks', () =>
    fetch('/api/v1/mobius/ansible/playbooks').then((res) => res.json())
  );

  const handleRunPlaybook = () => {
    if (selectedPlaybook && selectedHosts.length > 0 && onRunPlaybook) {
      onRunPlaybook(selectedPlaybook, selectedHosts);
    }
  };

  const handleHostSelection = (hostId: string, checked: boolean) => {
    if (checked) {
      setSelectedHosts([...selectedHosts, hostId]);
    } else {
      setSelectedHosts(selectedHosts.filter((id) => id !== hostId));
    }
  };

  const hostTableHeaders = [
    { title: 'Select', isSortable: false },
    { title: 'Hostname', isSortable: true },
    { title: 'IP Address', isSortable: true },
    { title: 'OS', isSortable: true },
    { title: 'Distribution', isSortable: true },
    { title: 'Status', isSortable: true },
    { title: 'Last Seen', isSortable: true },
  ];

  const hostTableData = hosts?.map((host) => [
    <input
      type="checkbox"
      checked={selectedHosts.includes(host.id)}
      onChange={(e) => handleHostSelection(host.id, e.target.checked)}
      key={`checkbox-${host.id}`}
    />,
    host.hostname,
    host.ip_address,
    host.operating_system,
    host.distribution || 'Unknown',
    <span
      className={`status-badge ${host.status.toLowerCase()}`}
      key={`status-${host.id}`}
    >
      {host.status}
    </span>,
    new Date(host.last_seen).toLocaleDateString(),
  ]);

  if (hostsLoading || playbooksLoading) {
    return <Spinner />;
  }

  if (hostsError || playbooksError) {
    return <div className="error">Error loading Mobius MDM data</div>;
  }

  return (
    <div className="ansible-mdm">
      <h2>Mobius MDM Management</h2>
      
      <div className="ansible-controls">
        <div className="playbook-selector">
          <label htmlFor="playbook-select">Select Playbook:</label>
          <select
            id="playbook-select"
            value={selectedPlaybook}
            onChange={(e) => setSelectedPlaybook(e.target.value)}
          >
            <option value="">Choose a playbook...</option>
            {playbooks?.map((playbook) => (
              <option key={playbook.id} value={playbook.id}>
                {playbook.name} - {playbook.description}
              </option>
            ))}
          </select>
        </div>
        
        <Button
          onClick={handleRunPlaybook}
          disabled={!selectedPlaybook || selectedHosts.length === 0}
          className="run-playbook-btn"
        >
          Run Playbook on Selected Hosts ({selectedHosts.length})
        </Button>
      </div>

      <div className="hosts-table">
        <h3>Managed Hosts</h3>
        <TableContainer
          columnConfigs={hostTableHeaders}
          data={hostTableData || []}
          isLoading={hostsLoading}
          resultsTitle="hosts"
          emptyComponent={() => <div>No hosts available</div>}
          showMarkAllPages={false}
          isAllPagesSelected={false}
          disableTableHeader={false}
          disableCount={false}
        />
      </div>
    </div>
  );
};

export default AnsibleMDM;
