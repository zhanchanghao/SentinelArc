<template>
  <div class="single-page">
    <div class="app-shell">
      <header class="topbar">
        <div class="topbar-inner">
          <div class="brand">
            <div class="brand-mark" aria-hidden="true"></div>
            <div class="brand-text">
              <div class="brand-name">Skill 哨卫安全检查 · Sentinel</div>
              <div class="brand-subtitle">Single Page · Scan · Report</div>
            </div>
          </div>
        </div>
      </header>

      <main class="page">
        <UploadPage />
      </main>
    </div>
  </div>
</template>

<script setup lang="ts">
import UploadPage from './views/UploadPage.vue'
</script>
