class Firework {
    constructor(canvas) {
        this.canvas = canvas;
        this.ctx = canvas.getContext('2d');
        this.particles = [];
        this.numberOfParticles = 50;
        this.colors = ['#FF0000', '#FFD700', '#FF69B4', '#00FF00', '#4169E1', '#FF4500'];
        
        this.resize();
        window.addEventListener('resize', () => this.resize());
        this.animate();
        
        // 每隔2-4秒创建新烟花
        setInterval(() => this.createFirework(), Math.random() * 2000 + 2000);
    }

    resize() {
        this.canvas.width = window.innerWidth;
        this.canvas.height = window.innerHeight;
    }

    createParticle(x, y, color) {
        return {
            x,
            y,
            color,
            velocity: {
                x: (Math.random() - 0.5) * 8,
                y: (Math.random() - 0.5) * 8
            },
            alpha: 1,
            life: Math.random() * 50 + 50
        };
    }

    createFirework() {
        const x = Math.random() * this.canvas.width;
        const y = Math.random() * (this.canvas.height * 0.5) + this.canvas.height * 0.3;
        const color = this.colors[Math.floor(Math.random() * this.colors.length)];

        for (let i = 0; i < this.numberOfParticles; i++) {
            this.particles.push(this.createParticle(x, y, color));
        }
    }

    animate() {
        this.ctx.fillStyle = 'rgba(255, 255, 255, 0.2)';
        this.ctx.fillRect(0, 0, this.canvas.width, this.canvas.height);

        this.particles.forEach((particle, index) => {
            particle.velocity.y += 0.05; // 重力
            particle.x += particle.velocity.x;
            particle.y += particle.velocity.y;
            particle.alpha -= 0.005;
            particle.life--;

            if (particle.life <= 0) {
                this.particles.splice(index, 1);
            }

            this.ctx.beginPath();
            this.ctx.arc(particle.x, particle.y, 2, 0, Math.PI * 2);
            this.ctx.fillStyle = `rgba(${this.hexToRgb(particle.color)}, ${particle.alpha})`;
            this.ctx.fill();
        });

        requestAnimationFrame(() => this.animate());
    }

    hexToRgb(hex) {
        const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
        return result ? 
            `${parseInt(result[1], 16)}, ${parseInt(result[2], 16)}, ${parseInt(result[3], 16)}` : 
            '255, 255, 255';
    }
}

// 初始化烟花效果
window.addEventListener('load', () => {
    const canvas = document.getElementById('fireworks');
    new Firework(canvas);
}); 