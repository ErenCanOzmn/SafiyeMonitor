// Safiye mascot: a calico cat that walks along the bottom of the window using
// real sprite frames (extracted from the project sprite sheet). It walks with a
// 6-frame gait, turns at the screen edges, occasionally does a somersault, and
// rains pixel hearts when you click it.
(function () {
    var cv = document.getElementById('sfcat');
    if (!cv) return;
    var ctx = cv.getContext('2d');
    ctx.imageSmoothingEnabled = false;

    var walkImg = new Image();
    var rollImg = new Image();
    var loaded = 0;
    function ready() { if (++loaded === 2) start(); }
    walkImg.onload = ready;
    rollImg.onload = ready;
    walkImg.src = '/static/cat_walk.png?v=3';
    rollImg.src = '/static/cat_roll.png?v=1';

    var HEART = [            // 7x6 pixel-art heart
        [0, 1, 1, 0, 1, 1, 0],
        [1, 1, 1, 1, 1, 1, 1],
        [1, 1, 1, 1, 1, 1, 1],
        [0, 1, 1, 1, 1, 1, 0],
        [0, 0, 1, 1, 1, 0, 0],
        [0, 0, 0, 1, 0, 0, 0]
    ];

    function start() {
        var WF = 6, RF = 8;
        var cw = Math.round(walkImg.width / WF), ch = walkImg.height;
        var rw = Math.round(rollImg.width / RF), rh = rollImg.height;

        var PAD_TOP = 92;                       // headroom for floating hearts
        var W = Math.max(cw, rw) + 24;
        var H = ch + PAD_TOP;
        cv.width = W; cv.height = H;
        var baseline = H;                       // feet sit on the canvas bottom

        var x = Math.random() * Math.max(0, window.innerWidth - W);
        var dir = Math.random() < 0.5 ? 1 : -1; // 1 = moving right, -1 = left
        var speed = 0.5;

        var state = 'walk';
        var frame = 0, ftick = 0;
        var WALK_DUR = 14;                       // ticks per walk frame (higher = slower)
        var ROLL_DUR = 15;                       // 8 roll frames * 15 ticks ~= 2s @ 60fps
        var ROLL_PEAK = speed * 6;              // sudden X burst at the start of a roll
        var ROLL_DECAY = 0.93;                  // burst eases back down to walk speed
        var rollVel = 0;
        var ticks = 0, nextTrick = 420 + Math.random() * 600;

        var hearts = [];

        function spawnHearts() {
            for (var i = 0; i < 7; i++) {
                hearts.push({
                    x: W / 2 + (Math.random() * 28 - 14),
                    y: baseline - ch * 0.65,
                    vx: Math.random() * 0.6 - 0.3,
                    vy: -(0.55 + Math.random() * 0.7),
                    life: 1,
                    size: 3 + Math.floor(Math.random() * 2)
                });
            }
        }

        // Canvas is pointer-events:none so it never blocks the UI; detect clicks
        // that land on the cat via a window listener instead.
        window.addEventListener('click', function (e) {
            var r = cv.getBoundingClientRect();
            if (e.clientX >= r.left && e.clientX <= r.right &&
                e.clientY >= r.top && e.clientY <= r.bottom) {
                spawnHearts();
            }
        });

        function drawHeart(px, py, s, alpha) {
            ctx.globalAlpha = Math.max(0, Math.min(1, alpha));
            ctx.fillStyle = '#ff5d8f';
            for (var r = 0; r < HEART.length; r++)
                for (var c = 0; c < HEART[r].length; c++)
                    if (HEART[r][c]) ctx.fillRect(px + c * s, py + r * s, s, s);
            ctx.globalAlpha = 1;
        }

        function draw() {
            ctx.clearRect(0, 0, W, H);
            var img, cellW, cellH, sx;
            if (state === 'roll') { img = rollImg; cellW = rw; cellH = rh; sx = frame * rw; }
            else { img = walkImg; cellW = cw; cellH = ch; sx = frame * cw; }
            var dx = Math.round((W - cellW) / 2);
            var dy = baseline - cellH;
            ctx.save();
            if (dir === -1) { ctx.translate(W, 0); ctx.scale(-1, 1); } // sprites face right; flip when going left
            ctx.drawImage(img, sx, 0, cellW, cellH, dx, dy, cellW, cellH);
            ctx.restore();
            for (var i = 0; i < hearts.length; i++)
                drawHeart(hearts[i].x, hearts[i].y, hearts[i].size, hearts[i].life);
        }

        function moveBy(px) {
            x += dir * px;
            var maxX = window.innerWidth - W;
            if (x > maxX) { x = maxX; dir = -1; }
            if (x < 0) { x = 0; dir = 1; }
        }

        function tick() {
            ticks++;
            if (state === 'walk') {
                moveBy(speed);
                if (++ftick >= WALK_DUR) { ftick = 0; frame = (frame + 1) % WF; }
                if (ticks >= nextTrick) { state = 'roll'; frame = 0; ftick = 0; rollVel = ROLL_PEAK; }
            } else {                                  // somersault
                // sudden X burst that decays back to the normal walk speed
                rollVel = speed + (rollVel - speed) * ROLL_DECAY;
                moveBy(rollVel);
                if (++ftick >= ROLL_DUR) {
                    ftick = 0; frame++;
                    if (frame >= RF) {
                        state = 'walk'; frame = 0;
                        ticks = 0; nextTrick = 420 + Math.random() * 700;
                    }
                }
            }
            cv.style.left = x + 'px';

            for (var i = hearts.length - 1; i >= 0; i--) {
                var hh = hearts[i];
                hh.x += hh.vx; hh.y += hh.vy; hh.vy += 0.004; hh.life -= 0.011;
                if (hh.life <= 0) hearts.splice(i, 1);
            }

            draw();
            requestAnimationFrame(tick);
        }
        tick();
    }
})();
