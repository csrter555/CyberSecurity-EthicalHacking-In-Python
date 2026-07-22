<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>csrter555's Website</title>

<link rel="icon" type="image/png" href="logo2.png">
<link rel="shortcut icon" href="logo2.png">

<meta name="viewport" content="width=device-width, initial-scale=1.0">

<style>
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
    font-family: 'Segoe UI', sans-serif;
}

/* Background */
body {
    background: url("background.png") no-repeat center center fixed;
    background-size: cover;
    background-color: #111; /* fallback */
    min-height: 100vh;
    color: white;
}

/* Overlay */
.overlay {
    background: rgba(0, 0, 0, 0.65);
    min-height: 100vh;
    width: 100%;
    display: flex;
    flex-direction: column;
}

/* Navbar */
.navbar {
    display: flex;
    justify-content: space-between;
    padding: 20px 50px;
}

.navbar h1 {
    font-size: 1.5rem;
}

.navbar a {
    color: white;
    text-decoration: none;
    margin-left: 20px;
    font-size: 0.9rem;
    transition: 0.2s;
}

.navbar a:hover {
    color: #ff7a00;
}

/* Hero */
.hero {
    flex: 1;
    display: flex;
    justify-content: center;
    align-items: center;
    text-align: center;
    padding: 20px;
}

.hero-content {
    max-width: 750px;
}

.hero h2 {
    font-size: 3rem;
    margin-bottom: 10px;
}

.hero p {
    color: #ccc;
    margin-bottom: 25px;
    line-height: 1.6;
}

/* Buttons */
.buttons a {
    text-decoration: none;
    padding: 12px 22px;
    border-radius: 8px;
    margin: 5px;
    display: inline-block;
    font-size: 0.95rem;
    transition: 0.2s;
}

.btn-primary {
    background: #ff7a00;
    color: white;
}

.btn-primary:hover {
    background: #ff9a33;
}

.btn-secondary {
    border: 1px solid white;
    color: white;
}

.btn-secondary:hover {
    background: white;
    color: black;
}

/* Footer */
.footer {
    text-align: center;
    padding: 15px;
    font-size: 0.8rem;
    color: #aaa;
}
</style>

</head>

<body>

<div class="overlay">

    <!-- Navbar -->
    <div class="navbar">
        <h1>Carter (csrter555)</h1>
        <div>
            <a href="index.html">Home</a>
            <a href="portfolio.html">Portfolio</a>
            <a href="contact.html">Contact</a>
        </div>
    </div>

    <!-- Hero -->
    <div class="hero">
        <div class="hero-content">
            <h2>Innovative. Delicate. Modern.</h2>
            <p>
                Work you'd pay millions for — at a price so affordable you'll double take.<br><br>
                Developer, Designer, and Systems Builder specializing in Discord bots, APIs, and UI/UX.
            </p>

            <div class="buttons">
                <a href="contact.html" class="btn-primary">Hire Me</a>
                <a href="portfolio.//.html" class="btn-secondary">View Work</a>
            </div>
        </div>
    </div>

    <!-- Footer -->
    <div class="footer">
        © 2026 Carter Moore — All Rights Reserved
    </div>

</div>

</body>
</html>