export interface IAnsibleHost {
  id: string;
  hostname: string;
  ip_address: string;
  operating_system: string;
  status: 'online' | 'offline' | 'pending';
  last_seen: string;
  ansible_facts?: { [key: string]: any };
  osquery_enrolled: boolean;
  distribution?: 'Ubuntu' | 'Pop!_OS' | 'Debian' | 'RHEL' | 'CentOS' | 'macOS' | 'Windows';
}

export interface IAnsiblePlaybook {
  id: string;
  name: string;
  description: string;
  path: string;
  tags: string[];
  variables?: { [key: string]: any };
  created_at: string;
  updated_at: string;
}

export interface IAnsibleJob {
  id: string;
  playbook_id: string;
  host_ids: string[];
  status: 'pending' | 'running' | 'completed' | 'failed';
  started_at?: string;
  finished_at?: string;
  output?: string;
  error?: string;
}
