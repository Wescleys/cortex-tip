document.addEventListener("DOMContentLoaded", () => {
    // Verifica se estamos na página de Dashboard (tem gráfico) ou na Busca
    if (document.getElementById('iocChart')) {
        // Se for Dashboard, o loader espera o gráfico
        carregarDashboard();
    } else {
        // Se for outra página (Busca), fecha o loader assim que o HTML estiver pronto
        // Damos um pequeno delay de 500ms para ficar suave
        setTimeout(esconderLoader, 500);
    }
});

let iocChart = null;

// Função para esconder a tela de carregamento
function esconderLoader() {
    const loader = document.getElementById("page-loader");
    if (loader) {
        loader.classList.add("loader-hidden");
        loader.addEventListener("transitionend", () => {
            loader.remove(); // Remove do HTML para liberar memória
        });
    }
}

function carregarDashboard() {
    // Inicia o fetch dos dados
    fetch("/status")
        .then(response => response.json())
        .then(data => {
            console.log("Dados recebidos:", data);

            // 1. Atualizar Texto de Status
            const statusElem = document.getElementById("last-update");
            if(statusElem) statusElem.innerText = data.status;

            // 2. Pegar os números
            const counts = data.ioc_counts || {};
            const ips = counts.ips || 0;
            const urls = counts.urls || 0;
            const domains = counts.domains || 0;
            const hashes = counts.filehashs || 0;

            // 3. Animar Números
            animateValue("count-ips", 0, ips, 1000);
            animateValue("count-urls", 0, urls, 1000);
            animateValue("count-domains", 0, domains, 1000);
            animateValue("count-hashes", 0, hashes, 1000);

            // 4. Renderizar Gráfico
            renderChart(ips, urls, domains, hashes);
            
            // 5. O GRANDE TRUQUE: 
            // Só escondemos o loader AGORA, depois que tudo foi processado.
            // Coloquei um delay mínimo de 800ms para a animação não ser um "piscar" se a internet for ultra rápida.
            setTimeout(esconderLoader, 800); 
        })
        .catch(error => {
            console.error("Erro ao carregar dashboard:", error);
            // Se der erro, escondemos o loader para não travar a tela preta
            esconderLoader();
            if(document.getElementById("last-update")) {
                document.getElementById("last-update").innerText = "Erro de conexão";
            }
        });
}

function renderChart(ips, urls, domains, hashes) {
    const ctx = document.getElementById('iocChart');
    if (!ctx) return; // Segurança caso o elemento não exista

    if (iocChart) {
        iocChart.destroy();
    }

    iocChart = new Chart(ctx.getContext('2d'), {
        type: 'bar',
        data: {
            labels: ['IPs', 'URLs', 'Domínios', 'Hashes'],
            datasets: [{
                label: 'Quantidade',
                data: [ips, urls, domains, hashes],
                backgroundColor: [
                    'rgba(33, 150, 243, 0.7)', 
                    'rgba(255, 152, 0, 0.7)',  
                    'rgba(76, 175, 80, 0.7)',  
                    'rgba(244, 67, 54, 0.7)'   
                ],
                borderColor: [
                    'rgba(33, 150, 243, 1)',
                    'rgba(255, 152, 0, 1)',
                    'rgba(76, 175, 80, 1)',
                    'rgba(244, 67, 54, 1)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: {
                duration: 1500, // Animação do gráfico subindo
                easing: 'easeOutQuart'
            },
            plugins: {
                legend: { display: false },
                title: {
                    display: true,
                    text: 'Distribuição de Ameaças',
                    color: '#fff',
                    font: { size: 16 }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    grid: { color: '#30363d' },
                    ticks: { color: '#8b949e' }
                },
                x: {
                    grid: { display: false },
                    ticks: { color: '#8b949e' }
                }
            }
        }
    });
}

function animateValue(id, start, end, duration) {
    let obj = document.getElementById(id);
    if (!obj) return;
    
    let range = end - start;
    let minTimer = 50;
    let stepTime = Math.abs(Math.floor(duration / range));
    stepTime = Math.max(stepTime, minTimer);
    
    let startTime = new Date().getTime();
    let endTime = startTime + duration;
    let timer;
  
    function run() {
        let now = new Date().getTime();
        let remaining = Math.max((endTime - now) / duration, 0);
        let value = Math.round(end - (remaining * range));
        obj.innerHTML = value.toLocaleString();
        if (value == end) {
            clearInterval(timer);
        }
    }
    
    timer = setInterval(run, stepTime);
    run();
}

// Enter na busca rápida
function handleKeyPress(event) {
    if (event.key === "Enter") {
        let val = document.getElementById("quickSearch").value;
        if(val.length >= 3) {
            window.location.href = `/search?query=${encodeURIComponent(val)}`;
        } else {
            alert("Digite pelo menos 3 caracteres.");
        }
    }
}