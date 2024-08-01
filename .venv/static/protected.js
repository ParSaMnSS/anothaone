// Make a request to the /login endpoint to get the access token
fetch('/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      email: 'your_email@example.com',
      password: 'your_password'
    })
  })
    .then(response => response.json())
    .then(data => {
      const accessToken = data.access_token;
  
      // Make a request to the /protected endpoint with the access token
      fetch('/protected', {
        headers: {
          'Authorization': `Bearer ${accessToken}`
        }
      })
        .then(response => response.json())
        .then(data => console.log(data))
        .catch(error => console.error(error));
    })
    .catch(error => console.error(error));