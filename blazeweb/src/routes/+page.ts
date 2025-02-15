import type { PageLoad } from "$./types";

export const load: PageLoad = async ({ fetch, params }) => {
	const res = await fetch("/api/networks");
	const item = await res.json();
	return { item };
};
