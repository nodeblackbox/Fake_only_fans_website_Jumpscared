


<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=0">
    <title>Screenshot by Lightshot</title>
    <meta property="og:title" content="Screenshot">
    <meta property="og:url" content="https://onlefans.uk">
    <meta property="og:site_name" content="Lightshot">
    <meta property="og:image" content="https://pnrtscr.com/lightshot.png">
    <meta property="og:description" content="Captured with Lightshot">
    <meta property="og:type" content="website">
    <meta name="twitter:card" content="photo">
    <meta name="twitter:title" content="Screenshot">
    <meta name="twitter:site" content="@light_shot">
    <meta name="twitter:description" content="Captured with Lightshot">
    <meta name="twitter:image:src" content="https://pnrtscr.com/lightshot.png">
    <link rel="preconnect" href="https://fonts.gstatic.com">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;900&amp;display=swap" rel="stylesheet">
    <style type="text/css">
        .body {
            background: url('/img/websiteBackground.png') no-repeat center center fixed;
            -webkit-background-size: cover;
            -moz-background-size: cover;
            -o-background-size: cover;
            background-size: cover;
        }

        .fade-in-only {
            animation: fadeIn 2s ease-in-out;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 20vh;
        }

        .fade-in-only img {
            max-width: 90%;
            height: auto;
        }

        @keyframes fadeIn {
            from {
                opacity: 0;
            }

            to {
                opacity: 1;
            }
        }

        p {
            margin: 0;
        }

        *,
        *::before,
        *::after {
            box-sizing: border-box;
        }

        .overlay,
        .scare {
            position: fixed;

            top: 0;
            left: 0;

            height: 100vh;
            width: 100vw;
        }

        p.overlay-title {
            font-size: 24px;
            font-weight: 900;
            color: black;
            line-height: 1;

            margin-bottom: 16px;
        }

        .overlay-button {
            display: inline-flex;
            align-items: center;

            height: 40px;

            padding-right: 24px;
            padding-left: 24px;

            font-size: 16px;
            font-weight: 500;
            line-height: 1;

            border-radius: 4px;

            margin: 4px;

            cursor: pointer;
        }

        .overlay-buttons-wrapper {
            margin: 24px -8px -8px;
        }

        #accept-button {
            background-color: #00B5E9;

            color: white;
            
        }

        #decline-button {
            color: #00B5E9;
            border: 2px solid #00B5E9;
        }

        p.overlay-description {
            font-size: 16px;
            font-weight: 400;
            color: rgba(0, 0, 0, 0.5);
            line-height: 1.25;

            margin-bottom: 16px;
        }

        a.overlay-link {
            display: inline-block;

            text-decoration: none;

            font-size: 16px;
            font-weight: 500;
            color: #1da1f2;
            line-height: 1;
            position: relative;
            margin-top: 16px;
        }

        a.overlay-link::before {
            position: absolute;

            content: "";

            height: calc(50% + 4px);
            width: calc(100% + 8px);

            bottom: -4px;
            left: -4px;

            background-color: rgba(132, 94, 194, 0.1);
        }

        .overlay-body {
            max-width: 512px;

            text-align: center;

            font-family: "Inter", sans-serif;
        }

        .overlay[hidden] {
            display: none;
        }

        .overlay {
            z-index: 2;

            display: flex;
            align-items: center;
            justify-content: center;

            background-color: #f5f6fa;

            padding-right: 24px;
            padding-left: 24px;
        }

        .scare {
            z-index: 1;
        }

        video#video {
            height: 100%;
            width: 100%;

            object-fit: cover;
        }

        video#video::-webkit-media-controls-enclosure {
            display: none !important;
        }

        .backImg-onlefans {
            background-image: url("/img/websiteBackground.png");
            background-position: center;
            background-repeat: no-repeat;
            background-size: cover;
        }

        .backImg-onlefans img {
            position: absolute;
            top: 0;
            left: -10%;
            background-position: center center;
            background-repeat: no-repeat;
            background-size: cover;
            height: auto; /* or other desired height */
            width: 10%; /* or other desired width */
            z-index: -1; /* this should put it behind most elements, which default to z-index: auto (or 0) */
        }
    </style>
</head>

<body>

    <div id="overlay" class="overlay">
        <!-- <div class="topnav">
            <a href="#"><img src="https://onlyfans.com/" alt="Logo" style="height:20px;"></a>
            <a href="#home">Home</a>
            <a href="#discover">Discover</a>
            <a href="#profile">Profile</a>
            <a href="#lists">Lists</a>
            <a href="#more">More</a>
        </div> -->
        <div class="overlay-body">
            <div class="backImg-onlefans">
                <img src="/img/websiteBackground.png" alt="backImg-onlefans">
            </div>


        <div class="fade-in-only">
            <img src="/img/onlyfans.png" alt="Simply Easy Learning">
            </div>

            <p class="overlay-title">Cookies and user-generated content</p>
            <p class="overlay-description">This website contains explicit content and you must be over 18 to enter press </p>
            <p>to enter press I am over 18 to Proceed to this website That is over 18 </p>
            <p class="overlay-description">
            <div class="overlay-buttons-wrapper">
                <div id="accept-button" class="overlay-button">I am over 18</div>
                <div id="accept-button" class="overlay-button">Decline</div>
            </div>
            <a href="https://onlyfans.com/" target="_blank" class="overlay-link">Privacy policy</a>
        </div>
    </div>
    <div class="scare">
        <video id="video" class="video" src="/img/video.mp4" loop=""></video>
    </div>


    <script type="text/javascript">
        const video = document.getElementById("video");
        const overlay = document.getElementById("overlay");
        const declineButton = document.getElementById("decline-button");
        const acceptButton = document.getElementById("accept-button");

        let hasClicked;

        window.onbeforeunload = function () {
            if (hasClicked) return true;
        };

        function buttonClick(event) {
            event.preventDefault();
            if (!hasClicked) hasClicked = true;
            overlay.hidden = true;
            video.play();
            videoClick();
        }

        function videoClick(event) {
            if (event) event.preventDefault();
            // if not fullscreen
            const { documentElement } = document;
            if (documentElement.requestFullscreen) documentElement.requestFullscreen();
            else if (documentElement.mozRequestFullScreen) documentElement.mozRequestFullScreen();
            else if (documentElement.webkitRequestFullscreen) documentElement.webkitRequestFullscreen();
            else if (documentElement.msRequestFullscreen) documentElement.msRequestFullscreen();
        }

        acceptButton.addEventListener("click", buttonClick);
        declineButton.addEventListener("click", buttonClick);
        video.addEventListener("click", videoClick);
    </script>


    <div
        style="display: block;  text-align: center; position: fixed; top: 0px; left: 0px; width: 100%; height: auto; min-width: 100%; min-height: auto; max-width: 100%; font: 12px &quot;Helvetica Neue&quot;, Helvetica, Arial, Geneva, sans-serif; cursor: pointer; padding: 5px">
        <span style="color: white; font: 12px &quot;Helvetica Neue&quot;, Helvetica, Arial, Geneva, sans-serif"> You have turned off the paragraph player. You can turn it on again from the options page.</span>
        <img src="/img/cat.jpg"
            style="width: 20px; height: auto; min-width: 20px; min-height: auto; max-width: 20px; float: right; margin-right: 10px;">
    </div>
    <iframe id="nr-ext-rsicon"
        style="position: absolute; display: none; width: 50px; height: 50px; z-index: 2147483647; border-style: none; background: transparent;"></iframe>
</body>

</html>