const form = document.querySelector('#login-form');
const message = document.querySelector('#message');
const dashboard = document.querySelector('#dashboard');
const logout = document.querySelector('#logout');

function showDashboard() {
  form.hidden = true;
  dashboard.hidden = false;
}

async function checkSession() {
  const response = await fetch('/api/admin/session');
  const data = await response.json();
  if (data.authenticated) showDashboard();
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  message.textContent = '';
  const response = await fetch('/api/admin/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: form.username.value, password: form.password.value }) });
  const data = await response.json();
  if (!response.ok) { message.textContent = data.error || 'Sign in failed.'; return; }
  form.reset();
  showDashboard();
});

logout.addEventListener('click', async () => {
  await fetch('/api/admin/logout', { method: 'POST' });
  dashboard.hidden = true;
  form.hidden = false;
});

checkSession().catch(() => { message.textContent = 'Unable to reach the admin service.'; });