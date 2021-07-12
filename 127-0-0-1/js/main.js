var def = '?????1234567890???????????ABCDEF';
var as = 'ЯЙЪЁёЬ???? ?????????????????????IVXLCDM0987654321';
var as_s = 'Я Й Ъ Ё ё Ь ? ? ? ?   ?????????????????????IVXLCDM0987654321';
var en = 'WakeUpNeo,TheMatrixHasYou????????1234567890????????????????????????0987654321';
var en_s = 'W a k e U p N e o ,T h e M a t r i x H a s Y o u ????????1234567890????????????????????????0987654321';
var ru = 'ОчнисьНео,МатрицаОвладеваетТобой????1234567890????????????????????????????0987654321';
var ru_s = 'О ч н и с ь Н е о ,М а т р и ц а О в л а д е в а е т Т о б о й ????1234567890????????????????????????????0987654321';
var ar_s = '1234567890? ? ? ? ? ? ? ? ? ? ? ? ? ?  ? ? ? ? ';
var ch = '??????????????????????????????????';
var ch_s = '? ? ? ? ? ? ? ? ? ? ? ???????????????????????';
 
function TheMatrixRain(charset) {
 
    var c = document.getElementById('canvas');
    var ctx = c.getContext('2d');
    c.height = window.innerHeight;
    c.width = window.innerWidth;
 
    var font_size = 10;
    var columns = c.width/font_size;
    var drops = [];
 
    for (var x = 0; x < columns; x++) {
        drops[x] = 1;
    }
 
    characters = charset.split('');
 
    var rnd = drops.slice();
 
    setInterval(draw, 30);
 
    function draw() {
 
        if (Math.random() > 0.25) {
            ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
            var x_rect = Math.floor(Math.random()*c.width);
            var y_rect = Math.floor(Math.random()*c.height);
            ctx.fillRect(x_rect, y_rect, (c.width/4), ((c.height/c.height)*(font_size*10)));
        }
 
        ctx.fillStyle = 'rgba(0, 0, 0, 0.03)';
        ctx.fillRect(0, 0, c.width, c.height);
        ctx.fillStyle = '#0F0';
 
 
 
        for (var i = 0; i < drops.length; i++) {
 
         if (drops[i]*font_size < c.height) {
 
            var text = characters[Math.floor(Math.random()*characters.length)];
            var col_size = font_size;
 
            if (!(i%2)) {
                if(drops[i] == 1) {
                   rnd[i] = Math.random() * (1.5 - 0.7) + 0.7;     
                }
                col_size /= rnd[i];
            }
 
            if (!(i%3)) {
                if(drops[i] == 0) {
                   rnd[i] = Math.random() * (1.5 - 0.7) + 0.7;     
                }
               col_size /= rnd[i]; 
            }
 
 
            ctx.font = col_size + 'px arial';
 
            ctx.fillText(text, i*font_size, drops[i]*font_size);
 
            }
 
           if (drops[i]*font_size > c.height && Math.random() > 0.965) {
                ctx.fillStyle = 'rgba(0, 0, 0, 1)';
                ctx.fillRect(i*font_size, 0, font_size, c.height);
                ctx.fillStyle = 'rgba(0, 188, 0, 0.5)';
                drops[i] = 0;
 
            }
 
            drops[i]++ 
 
       }
 
    }
}
TheMatrixRain (en_s);

// TO GET IP
$.getJSON("https://api.ipify.org?format=json",
        function(data) {
            $("#IP").html(data.ip);
        })

// TO GET TIME
var dt = new Date();
document.getElementById("TIME").innerHTML = dt.toLocaleString();