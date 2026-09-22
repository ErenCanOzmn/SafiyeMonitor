// Reference-matched illustrated Safiye. A twelve-pose atlas replaces pixel sprites.
// Motion is measured in seconds; the atlas is aligned once when it loads.
(() => {
    'use strict';
    const canvas = document.getElementById('sfcat');
    const context = canvas?.getContext('2d');
    if (!context) return;
    canvas.setAttribute('aria-hidden', 'true');

    const walk = new Image();
    walk.onload = start;
    walk.onerror = () => { canvas.hidden = true; };
    walk.src = '/static/safiye-walk-atlas.png?v=1';

    // Read sprite extents to keep paws on the same baseline across all poses.
    // Original asset pixels are preserved; this is ordinary atlas rendering.
    function atlasFrames() {
        const columns = 4, rows = 3;
        const cellWidth = walk.width / columns, cellHeight = walk.height / rows;
        const scratch = document.createElement('canvas');
        scratch.width = walk.width; scratch.height = walk.height;
        const sample = scratch.getContext('2d', { willReadFrequently: true });
        sample.drawImage(walk, 0, 0);
        const pixels = sample.getImageData(0, 0, walk.width, walk.height).data;
        const frames = [];
        for (let index = 0; index < columns * rows; index++) {
            const left = Math.round(index % columns * cellWidth);
            const top = Math.round(Math.floor(index / columns) * cellHeight);
            const right = Math.round((index % columns + 1) * cellWidth);
            const bottom = Math.round((Math.floor(index / columns) + 1) * cellHeight);
            let minX = right, maxX = left, minY = bottom, maxY = top;
            for (let y = top; y < bottom; y++) {
                for (let x = left; x < right; x++) {
                    if (pixels[(y * walk.width + x) * 4 + 3] > 32) {
                        minX = Math.min(minX, x); maxX = Math.max(maxX, x);
                        minY = Math.min(minY, y); maxY = Math.max(maxY, y);
                    }
                }
            }
            if (minX > maxX || minY > maxY) {
                frames.push({ x: left, y: top, width: cellWidth, height: cellHeight });
            } else {
                frames.push({ x: Math.max(left, minX - 2), y: Math.max(top, minY - 2),
                    width: Math.min(right, maxX + 3) - Math.max(left, minX - 2),
                    height: Math.min(bottom, maxY + 3) - Math.max(top, minY - 2) });
            }
        }
        return frames;
    }

    function start() {
        const WIDTH = 150, HEIGHT = 140, BASELINE = 135;
        const SPEED = 36, WALK_FPS = 18, TURN_SECONDS = 0.64;
        const poses = atlasFrames();
        const spriteScale = Math.min(130 / Math.max(...poses.map(pose => pose.width)), 94 / Math.max(...poses.map(pose => pose.height)));
        const spriteHeight = Math.max(...poses.map(pose => pose.height)) * spriteScale;
        const clamp = (value, min, max) => Math.min(max, Math.max(min, value));
        const smooth = value => value * value * (3 - 2 * value);
        let reduced = document.body.classList.contains('reduce-motion');
        let frameId = null, lastTime = null, mode = 'walk';
        let x = 0, velocity = 0, direction = -1, gait = 0, phase = 0;
        let nextPause = 14 + Math.random() * 12, idleDuration = 1.6;
        let minX = 10, maxX = 10, pixelRatio = 1;
        let particles = [];

        function measure() {
            pixelRatio = Math.min(window.devicePixelRatio || 1, 3);
            canvas.width = Math.round(WIDTH * pixelRatio);
            canvas.height = Math.round(HEIGHT * pixelRatio);
            context.setTransform(pixelRatio, 0, 0, pixelRatio, 0, 0);
            context.imageSmoothingEnabled = true;
            context.imageSmoothingQuality = 'high';
            maxX = Math.max(minX, window.innerWidth - canvas.getBoundingClientRect().width - 10);
            x = clamp(x, minX, maxX);
        }
        measure();
        x = Math.max(minX, maxX - 55);

        function render() {
            context.clearRect(0, 0, WIDTH, HEIGHT);
            // The shadow stays on the ground while the body follows its gait.
            context.fillStyle = 'rgba(0, 0, 0, 0.22)';
            context.beginPath();
            context.ellipse(WIDTH / 2, BASELINE - 1, 38, 2.2, 0, 0, Math.PI * 2);
            context.fill();

            const frame = mode === 'walk' ? Math.floor(gait) % poses.length : 0;
            const pose = poses[frame];
            const drawWidth = pose.width * spriteScale;
            const drawHeight = pose.height * spriteScale;
            const bob = mode === 'walk' ? Math.sin(gait / poses.length * Math.PI * 4) * 0.35 : 0;
            const breathing = mode === 'idle' ? Math.sin(phase * 2.6) * 0.006 : 0;
            const turnProgress = mode === 'turn' ? clamp(phase / TURN_SECONDS, 0, 1) : 0;
            const facing = direction * (turnProgress > 0.5 ? -1 : 1);
            context.save();
            context.translate(WIDTH / 2, BASELINE + bob - Math.sin(turnProgress * Math.PI));
            context.scale(facing * (1 - Math.sin(turnProgress * Math.PI) * 0.06), 1 + breathing);
            context.drawImage(walk, pose.x, pose.y, pose.width, pose.height,
                -drawWidth / 2, -drawHeight, drawWidth, drawHeight);
            context.restore();

            // A small icy-blue glint on interaction, using the workspace accent.
            for (const particle of particles) {
                context.globalAlpha = Math.max(0, particle.life);
                context.fillStyle = particle.warm ? '#dcb994' : '#9cc5ff';
                context.fillRect(particle.x, particle.y, particle.size, particle.size);
            }
            context.globalAlpha = 1;
            canvas.style.transform = 'translate3d(' + x.toFixed(3) + 'px, 0, 0)';
        }

        function stop() {
            if (frameId !== null) cancelAnimationFrame(frameId);
            frameId = null;
            lastTime = null;
        }
        function schedule() {
            if (frameId === null && !reduced && !document.hidden) frameId = requestAnimationFrame(tick);
        }
        function park() {
            stop();
            mode = 'idle';
            phase = 0;
            velocity = 0;
            particles = [];
            render();
        }
        function tick(timestamp) {
            frameId = null;
            if (reduced || document.hidden) { lastTime = null; return; }
            const dt = lastTime === null ? 0 : Math.min((timestamp - lastTime) / 1000, 0.05);
            lastTime = timestamp;
            phase += dt;
            if (mode === 'walk') {
                const remaining = direction > 0 ? maxX - x : x - minX;
                const approach = 0.18 + 0.82 * smooth(clamp(remaining / 58, 0, 1));
                const desired = direction * SPEED * approach;
                velocity += (desired - velocity) * (1 - Math.exp(-dt * 5));
                x = clamp(x + velocity * dt, minX, maxX);
                gait += WALK_FPS * dt * Math.max(0.22, Math.abs(velocity) / SPEED);
                nextPause -= dt;
                if (remaining < 1.2) {
                    mode = 'turn'; phase = 0; velocity = 0;
                } else if (nextPause <= 0) {
                    mode = 'idle';
                    phase = 0;
                    idleDuration = 1.3 + Math.random() * 1.4;
                }
            } else if (mode === 'turn') {
                if (phase >= TURN_SECONDS) {
                    direction *= -1;
                    mode = 'walk'; phase = 0; gait = 0;
                    nextPause = 14 + Math.random() * 14;
                }
            } else if (mode === 'idle') {
                velocity *= Math.exp(-dt * 9);
                x = clamp(x + velocity * dt, minX, maxX);
                if (phase >= idleDuration) {
                    mode = 'walk'; phase = 0; gait = 0;
                    nextPause = 14 + Math.random() * 14;
                }
            }
            particles = particles.filter(particle => {
                particle.x += particle.vx * dt;
                particle.y += particle.vy * dt;
                particle.vy += 7 * dt;
                particle.life -= dt * 0.9;
                return particle.life > 0;
            });
            render();
            schedule();
        }

        window.addEventListener('safiye:motion', event => {
            reduced = event.detail.reduced;
            if (reduced) park();
            else { mode = 'walk'; phase = 0; gait = 0; lastTime = null; schedule(); }
        });
        window.addEventListener('resize', () => { measure(); render(); });
        document.addEventListener('visibilitychange', () => {
            stop();
            if (!document.hidden) { measure(); render(); schedule(); }
        });
        window.addEventListener('click', event => {
            if (reduced || document.querySelector('dialog[open]')) return;
            // Never make a button or input click trigger the mascot.
            if (event.target.closest('button, input, textarea, select, a, label')) return;
            const rect = canvas.getBoundingClientRect();
            const localX = (event.clientX - rect.left) / rect.width * WIDTH;
            const localY = (event.clientY - rect.top) / rect.height * HEIGHT;
            if (localX < 10 || localX > WIDTH - 10 || localY < BASELINE - spriteHeight || localY > BASELINE) return;
            for (let i = 0; i < 5; i++) {
                particles.push({ x: WIDTH / 2 + (Math.random() - 0.5) * 22,
                    y: BASELINE - spriteHeight * 0.8, vx: (Math.random() - 0.5) * 16,
                    vy: -15 - Math.random() * 12, life: 1, size: 1.5 + Math.random(), warm: i === 0 });
            }
            particles = particles.slice(-15);
        });
        if (reduced) park();
        else { render(); schedule(); }
    }
})();
