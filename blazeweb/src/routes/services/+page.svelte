<script lang="ts">
	import {
		Button,
		ClickableTile,
		DataTable,
		Modal,
		TextInput,
		InlineNotification,
		Loading,
	} from "carbon-components-svelte";
	import type { PageProps } from "./$types";
	let { data }: PageProps = $props();
	console.log(data);

	let open = $state(false);
	let uri = $state("scoring.wrccdc.org");
	let error: string | null = $state(null);
	let loading = $state(false);

	async function importQuotient() {
		open = false;
		loading = true;
		console.log(uri);
		let resp = await fetch(
			"/api/services/quotient?" +
				new URLSearchParams({
					uri: uri,
				}).toString(),
		);
		if (resp.ok) {
			let resp = await fetch("/api/services");
			if (resp.ok) {
				console.log("Resp was ok");
				let item = await resp.json();
				data = { item };
			} else {
				error = await resp.text();
			}
		} else {
			error = await resp.text();
		}
		loading = false;
	}
</script>

{#if loading}
	<Loading />
{/if}
{#if data.item.length == 0}
	<h1>Nothing's here.</h1>
	<br />
	<Button on:click={() => (open = true)}>Import from Quotient</Button>
	<Modal
		bind:open
		modalHeading="Import from Quotient"
		primaryButtonText="Import"
		secondaryButtonText="Cancel"
		on:click:button--secondary={() => (open = false)}
		on:submit={importQuotient}
	>
		<TextInput labelText="Quotient URL" name="uri" bind:value={uri} />
	</Modal>
{:else}
	<ClickableTile>
		<DataTable
			headers={[
				{ key: "key", value: "Key" },
				{ key: "value", value: "Value" },
			]}
			rows={data.item.map((item) => {
				return { id: item.name, key: "Name", value: item.name };
			})}
		/>
	</ClickableTile>
{/if}
{#if error !== null}
	<InlineNotification
		title="Error"
		subtitle={error}
		on:close={() => (error = null)}
	/>
{/if}
