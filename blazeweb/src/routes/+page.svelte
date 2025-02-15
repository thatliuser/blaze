<script lang="ts">
	import { ClickableTile, DataTable } from "carbon-components-svelte";
	import type { PageProps } from "./$types";
	let { data }: PageProps = $props();
	console.log(data);
</script>
{#each data.item as item}
	<ClickableTile>
		<h1>{item.cidr}</h1>
		<DataTable
			headers={[
				{ key: "key", value: "Key" },
				{ key: "value", value: "Value" },
			]}
			rows={[
				{
					id: "a",
					key: "Linux root",
					value: item.linux_root,
				},
				{
					id: "b",
					key: "Windows root",
					value: item.windows_root,
				},
				{
					id: "c",
					key: "Default password",
					value: item.default_pass,
				},
			]}
		/>
	</ClickableTile>
{/each}

