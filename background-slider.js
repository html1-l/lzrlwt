class BackgroundSlider {
    constructor() {
        this.images = [
            'personal-photo..jpg',
            'personal-photo.2.jpg',
            'personal-photo.3.jpg',
            'personal-photo.4.jpg'
        ];
        this.currentIndex = 0;
        this.init();
    }

    init() {
        // 每5秒切换一次背景
        setInterval(() => this.changeBackground(), 5000);
    }

    changeBackground() {
        this.currentIndex = (this.currentIndex + 1) % this.images.length;
        
        // 修改获取样式规则的方式，使其更可靠
        let beforeRule;
        for (let i = 0; i < document.styleSheets.length; i++) {
            const styleSheet = document.styleSheets[i];
            try {
                const rules = styleSheet.cssRules || styleSheet.rules;
                for (let j = 0; j < rules.length; j++) {
                    if (rules[j].selectorText === 'body::before') {
                        beforeRule = rules[j];
                        break;
                    }
                }
                if (beforeRule) break;
            } catch (e) {
                continue; // 跳过无法访问的样式表
            }
        }
        
        if (beforeRule) {
            // 添加淡入效果
            document.body.classList.remove('bg-fade');
            void document.body.offsetWidth; // 触发重绘
            document.body.classList.add('bg-fade');

            // 更改背景图片
            beforeRule.style.backgroundImage = `url('${this.images[this.currentIndex]}')`;
        }
    }
}

// 初始化背景轮播
window.addEventListener('load', () => {
    new BackgroundSlider();
}); 