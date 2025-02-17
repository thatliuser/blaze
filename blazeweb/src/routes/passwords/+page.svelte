<script lang="ts">
	import {
		ClickableTile,
		DataTable,
		FileUploader,
	} from "carbon-components-svelte";
	import type { PageProps } from "./$types";
	let { data }: PageProps = $props();
	console.log(data);

	type Password = {
		id: number;
		password: string;
	};

	let passwords: Password[] = $state([]);

	async function addPasswords(event: CustomEvent<readonly File[]>) {
		let files = event.detail;
		if (files.length != 1) {
			console.log("Ignoring");
			return;
		}
		let resp = await fetch("/api/passwords", {
			method: "POST",
			body: await files[0].text(),
		});
		// TODO: Actually type this correctly instead of this shit
		if (resp.ok) {
			passwords = await resp.json();
		} else {
			console.log("failed");
		}
	}
</script>

{#if passwords.length == 0}
	<h1>Nothing's here.</h1>
	<br />
	<FileUploader
		labelTitle="Upload passwords"
		buttonLabel="Import CSV"
		accept={[".csv"]}
		status="complete"
		on:add={addPasswords}
	/>
{:else}
	<ClickableTile>
		<DataTable
			headers={[
				{ key: "num", value: "Number" },
				{ key: "password", value: "Password" },
			]}
			rows={passwords.map((password) => {
				return {
					id: password.id,
					num: password.id,
					password: password.password,
				};
			})}
		/>
	</ClickableTile>
{/if}
