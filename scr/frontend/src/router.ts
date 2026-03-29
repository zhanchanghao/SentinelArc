import { createRouter, createWebHistory } from 'vue-router'

import UploadPage from './views/UploadPage.vue'

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', redirect: '/upload' },
    { path: '/upload', component: UploadPage, meta: { title: '上传' } },
  ],
})

