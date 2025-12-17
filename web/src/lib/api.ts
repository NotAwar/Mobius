import { writable } from 'svelte/store';

const API_BASE = 'http://localhost:3000/api/v1';

export interface ClusterStatus {
	status: string;
	nodes: number;
	version: string;
	ready: boolean;
}

export interface PostgresStatus {
	status: string;
	operator: string;
	databases: number;
	ready: boolean;
}

export interface HeadscaleStatus {
	status: string;
	users: number;
	nodes: number;
	ready: boolean;
}

export const clusterStatus = writable<ClusterStatus | null>(null);
export const postgresStatus = writable<PostgresStatus | null>(null);
export const headscaleStatus = writable<HeadscaleStatus | null>(null);

export async function fetchClusterStatus() {
	try {
		const response = await fetch(`${API_BASE}/status/cluster`);
		const data = await response.json();
		clusterStatus.set(data);
		return data;
	} catch (error) {
		console.error('Failed to fetch cluster status:', error);
		return null;
	}
}

export async function fetchPostgresStatus() {
	try {
		const response = await fetch(`${API_BASE}/status/postgres`);
		const data = await response.json();
		postgresStatus.set(data);
		return data;
	} catch (error) {
		console.error('Failed to fetch PostgreSQL status:', error);
		return null;
	}
}

export async function fetchHeadscaleStatus() {
	try {
		const response = await fetch(`${API_BASE}/status/headscale`);
		const data = await response.json();
		headscaleStatus.set(data);
		return data;
	} catch (error) {
		console.error('Failed to fetch Headscale status:', error);
		return null;
	}
}

export async function fetchHealth() {
	try {
		const response = await fetch(`${API_BASE}/health`);
		return await response.json();
	} catch (error) {
		console.error('Health check failed:', error);
		return null;
	}
}
