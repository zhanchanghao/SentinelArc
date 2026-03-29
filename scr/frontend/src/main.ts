import { createApp } from 'vue'
import './style.css'
import App from './App.vue'

if (window.location.pathname !== '/') {
  window.history.replaceState({}, '', '/')
}

createApp(App).mount('#app')
