let socket;
let authToken;


window.addEventListener('load', async () => {
    try {
        const response = await fetch('/api/check-session');
        const data = await response.json();
        
        if (data.isAuthenticated) {
            
            authToken = data.token; 
            document.getElementById('auth-container').classList.add('hidden');
            document.getElementById('chat-container').classList.remove('hidden');
            initializeChat(data.user.id);
        }
    } catch (error) {
        console.error('Session check failed:', error);
        showError('Failed to check session status');
    }
});

function showError(message) {
    const errorDiv = document.createElement('div');
    errorDiv.className = 'bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded fixed top-4 right-4';
    errorDiv.role = 'alert';
    errorDiv.innerHTML = `
        <strong class="font-bold">Error!</strong>
        <span class="block sm:inline"> ${message}</span>
    `;
    document.body.appendChild(errorDiv);
    setTimeout(() => errorDiv.remove(), 5000);
}

function toggleAuth() {
    const loginForm = document.getElementById('login-form');
    const registerForm = document.getElementById('register-form');
    loginForm.classList.toggle('hidden');
    registerForm.classList.toggle('hidden');
}

async function register() {
    const username = document.getElementById('register-username').value;
    const password = document.getElementById('register-password').value;

    if (!username || !password) {
        showError('Username and password are required');
        return;
    }

    try {
        const response = await fetch('/api/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, password }),
        });

        if (!response.ok) {
            const data = await response.json();
            throw new Error(data.error);
        }

        showSuccess('Registration successful! Please login.');
        toggleAuth();
    } catch (error) {
        showError(error.message);
    }
}

function showSuccess(message) {
    const successDiv = document.createElement('div');
    successDiv.className = 'bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded fixed top-4 right-4';
    successDiv.role = 'alert';
    successDiv.innerHTML = `
        <strong class="font-bold">Success!</strong>
        <span class="block sm:inline"> ${message}</span>
    `;
    document.body.appendChild(successDiv);
    setTimeout(() => successDiv.remove(), 5000);
}

async function login() {
    const username = document.getElementById('login-username').value;
    const password = document.getElementById('login-password').value;

    if (!username || !password) {
        showError('Username and password are required');
        return;
    }

    try {
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, password }),
        });

        if (!response.ok) {
            const data = await response.json();
            throw new Error(data.error);
        }

        const data = await response.json();
        authToken = data.token; 
        document.getElementById('auth-container').classList.add('hidden');
        document.getElementById('chat-container').classList.remove('hidden');
        initializeChat(data.user.id);
        showSuccess('Login successful!');
    } catch (error) {
        showError(error.message);
    }
}

async function logout() {
    try {
        await fetch('/api/logout', { method: 'POST' });
        if (socket) {
            socket.disconnect();
        }
        authToken = null;
        window.location.reload();
    } catch (error) {
        console.error('Logout failed:', error);
        showError('Failed to logout. Please try again.');
    }
}

function initializeChat(userId) {
    
    if (socket) {
        socket.disconnect();
    }

    
    socket = io({
        auth: {
            token: authToken,
            userId: userId
        }
    });

    
    socket.on('connect', () => {
        showSuccess('Connected to chat server');
        document.getElementById('message-input').disabled = false;
    });

    socket.on('disconnect', () => {
        document.getElementById('message-input').disabled = true;
        showError('Disconnected from chat server');
    });

    
    socket.on('connect_error', (error) => {
        console.error('Connection error:', error);
        if (error.message === 'Authentication required' || error.message === 'Invalid token') {
            showError('Authentication failed. Please login again.');
            setTimeout(() => window.location.reload(), 2000);
        } else if (error.message.includes('Too many connection attempts')) {
            showError('Too many connection attempts. Please wait a moment.');
        } else {
            showError(`Connection error: ${error.message}`);
        }
    });

    
    socket.on('previous-messages', (messages) => {
        const messagesContainer = document.getElementById('messages');
        messagesContainer.innerHTML = ''; 
        messages.forEach(message => {
            appendMessage(message);
        });
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    });

    
    socket.on('new-message', (message) => {
        appendMessage(message);
        const messagesContainer = document.getElementById('messages');
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    });

    
    socket.on('error', (error) => {
        showError(error.message);
    });
}

function appendMessage(message) {
    const messagesContainer = document.getElementById('messages');
    const messageElement = document.createElement('div');
    messageElement.className = 'p-3 rounded-lg';
    
    
    if (message.sender._id === socket.auth.userId) {
        messageElement.className += ' bg-blue-100 ml-auto max-w-[80%]';
    } else {
        messageElement.className += ' bg-gray-100 max-w-[80%]';
    }

    
    const sanitizedContent = document.createElement('div');
    sanitizedContent.textContent = message.content;

    messageElement.innerHTML = `
        <div class="font-bold text-sm text-gray-600">${message.sender.username}</div>
        <div class="mt-1">${sanitizedContent.textContent}</div>
        <div class="text-xs text-gray-500 mt-1">${new Date(message.timestamp).toLocaleString()}</div>
    `;
    
    messagesContainer.appendChild(messageElement);
}

function sendMessage() {
    const input = document.getElementById('message-input');
    const content = input.value.trim();
    
    if (!socket?.connected) {
        showError('Not connected to chat server');
        return;
    }

    if (!content) {
        return;
    }

    if (content.length > 1000) {
        showError('Message is too long (maximum 1000 characters)');
        return;
    }
    
    socket.emit('send-message', content);
    input.value = '';
}


document.getElementById('message-input').addEventListener('keypress', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
    }
});
