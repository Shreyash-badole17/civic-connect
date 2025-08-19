document.getElementById('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = document.getElementById('email').value.trim();
  const pw = document.getElementById('password').value.trim();
  const msg = document.getElementById('msg');

  if (!email || !pw) {
    msg.textContent = 'Please enter both fields.';
    return;
  }

  try {
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: pw })
    });
    const data = await res.json();
    if (res.ok) {
      msg.textContent = 'Login successful';
    } else {
      msg.textContent = data.error || 'Login failed';
    }
  } catch (err) {
    msg.textContent = 'Server error';
  }
});
