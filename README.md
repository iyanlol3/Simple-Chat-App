# Aplikasi Chat Real-time

Aplikasi chat real-time yang dibangun dengan Node.js, Express, Socket.IO, dan MongoDB, dilengkapi dengan autentikasi pengguna dan UI modern menggunakan Tailwind CSS.

## Fitur

- Pesan real-time menggunakan WebSocket (Socket.IO)
- Autentikasi pengguna dengan JWT
- UI modern dengan Tailwind CSS
- Riwayat pesan
- Penyimpanan database MongoDB

## Fitur Keamanan

### Autentikasi & Otorisasi
- **JWT (JSON Web Token)**: Digunakan untuk mengamankan koneksi WebSocket
- **Session Management**: Menggunakan express-session untuk mengelola sesi pengguna
- **Password Hashing**: Password dienkripsi menggunakan bcrypt sebelum disimpan
- **Middleware Auth**: Proteksi rute dan koneksi WebSocket memerlukan autentikasi

### Perlindungan WebSocket
- **Rate Limiting**: Membatasi jumlah koneksi per IP (100 koneksi per menit)
- **Token Verification**: Setiap koneksi WebSocket memerlukan token JWT yang valid
- **Connection Validation**: Validasi user ID dan token untuk setiap koneksi

### Keamanan Data & Input
- **XSS Protection**: Sanitasi konten pesan untuk mencegah Cross-Site Scripting
- **Input Validation**: Validasi panjang dan tipe data pesan
- **Message Size Limit**: Batasan ukuran pesan (maksimum 1000 karakter)

### Konfigurasi Keamanan
- **Environment Variables**: Penggunaan file .env untuk menyimpan konfigurasi sensitif
- **Secure Sessions**: Konfigurasi session dengan secret key terpisah
- **Production Ready**: Opsi secure cookie untuk environment produksi

### Error Handling
- **Graceful Error Handling**: Penanganan error yang aman untuk client
- **Safe Error Messages**: Pesan error yang informatif tanpa mengekspos detail sistem
- **Connection Recovery**: Penanganan otomatis untuk koneksi yang terputus

## Prasyarat

- Node.js (v14 atau lebih tinggi)
- MongoDB berjalan secara lokal atau string koneksi MongoDB Atlas

## Instalasi

1. Klon repositori
2. Instal dependensi:
   ```bash
   npm install
   ```
3. Buat file `.env` dengan variabel berikut:
   ```
   PORT=3000
   MONGODB_URI=mongodb://localhost:27017/chat-app
   JWT_SECRET=ganti-kunci-rahasia-ini-di-produksi
   ```

## Menjalankan Aplikasi

1. Mulai layanan MongoDB
2. Jalankan aplikasi:
   ```bash
   npm run dev
   ```
3. Buka http://localhost:3000 di browser Anda

## Penggunaan

1. Daftar akun baru
2. Masuk dengan kredensial Anda
3. Mulai mengobrol secara real-time!
