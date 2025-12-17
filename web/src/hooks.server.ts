import type { Handle } from '@sveltejs/kit';

// TODO: Add authentication when needed
const handleAuth: Handle = async ({ event, resolve }) => {
	// No authentication for now - this is a local development setup
	event.locals.user = null;
	event.locals.session = null;

	return resolve(event);
};

export const handle: Handle = handleAuth;
