<template>
	<Modal
		transition-name="fade"
		variant="hint-modal"
		@close="$router.back()"
	>
		<Card
			class="has-no-shadow"
			:title="$t('about.title')"
			:padding="false"
			:show-close="true"
			@close="$router.back()"
		>
			<div class="p-4">
				<p>
					{{ $t('about.version', {version: apiVersion}) }}
				</p>
			</div>
			<template #footer>
				<XButton
					variant="secondary"
					@click.prevent.stop="$router.back()"
				>
					{{ $t('misc.close') }}
				</XButton>
			</template>
		</Card>
	</Modal>
</template>

<script setup lang="ts">
import {computed} from 'vue'

import {useConfigStore} from '@/stores/config'

const configStore = useConfigStore()
const apiVersion = computed(() => configStore.version)
</script>
