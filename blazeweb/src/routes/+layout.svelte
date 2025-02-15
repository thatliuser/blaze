<script>
    import "carbon-components-svelte/css/g100.css";
    import { Header, HeaderNav, HeaderNavItem, Content } from "carbon-components-svelte";
</script>

<Header platformName="Blaze">
    <HeaderNav>
        <HeaderNavItem href="/" text="Dashboard"/>
        <HeaderNavItem href="/firewall" text="Firewall"/>
        <HeaderNavItem href="/services" text="Services"/>
        <HeaderNavItem href="/passwords" text="Passwords"/>
    </HeaderNav>
</Header>
<Content>
    <slot />
</Content>
