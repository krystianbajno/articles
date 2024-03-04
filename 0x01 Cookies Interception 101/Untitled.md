# Bezpieczeństwo w sieciach komputerowych – ESEJ

## Ataki z wykorzystaniem Buffer Overflow - Krystian Bajno 18530

### Czym jest Buffer Overflow?

Atak z wykorzystaniem przepełnienia bufora jest jednym z najgroźniejszych zagrożeń dla systemów informatycznych, a podatności są często podatnościami krytycznymi.

Aby zrozumieć tę podatność, warto najpierw przyjrzeć się działaniu pamięci komputerowej. Pamięć jest podzielona na różne obszary, w tym bufor, który jest przeznaczony do przechowywania danych tymczasowych.

Kiedy program próbuje zapisać więcej danych do bufora, niż jest on w stanie pomieścić, dochodzi do przepełnienia bufora – dzieje się to, gdy podatny interfejs wejścia do programu zostanie wykorzystany przez atakującego do wywołania błędu w programie.

Przepełnienie bufora prowadzi do nadpisania innych obszarów pamięci i wprowadzenia kodu złośliwego, który następnie może być wykonany.

### Ataki Buffer Overflow

Istnieje kilka rodzajów ataków wykorzystujących Buffer Overflow, takich jak "stack smashing" i "heap overflow".

Ścieżkę doprowadzającą do podatności Buffer Overflow, można wyznaczyć przy użyciu techniki zwanej „Harnessingiem”, z zamiarem znalezienia podatnej funkcji.

Następnie, można zastosować tak zwany „Spiking”, czyli wysyłanie dużej ilości losowych informacji w interfejs wejściowy w celu wywołania błędu.  

Kolejną techniką znajdowania tej podatności, jest Fuzzing, czyli wysyłanie losowych informacji w interfejsy wejściowe aplikacji, które mają za zadanie wywołać błąd krytyczny programu.

Istnieje kilka technik wykorzystania błędu, najczęściej błędu segmentacyjnego:

"Stack smashing" to atak polegający na nadpisaniu obszaru stosu programu, który przechowuje lokalne zmienne i dane funkcji. Atakujący może wykorzystać przepełnienie bufora, aby nadpisać adres powrotu funkcji, co prowadzi do wykonania kodu złośliwego umieszczonego w buforze.

"Heap overflow" to podobny atak, ale zamiast nadpisywać obszar stosu, atakujący nadpisuje dynamicznie alokowane dane przechowywane na stercie (heap). Ten rodzaj ataku może być trudniejszy do wykorzystania, ale może prowadzić do podobnych konsekwencji, takich jak zdalne wykonanie kodu.

Istnieją zabezpieczenia, takie jak zabezpieczenia typu - stack canary w stosie programu, który w przypadku przepełnienia, zasygnałuje wyłączenie programu, czy też NX bit – markujący pamięć jako nie wykonywalną – No Execute.  
  
Dodatkowo, istnieje zabezpieczenie ASLR (Address Space Layout Randomization), które losuje adresy w pamięci, aby utrudnić atakującemu wprowadzenie adresu, na który planował przeskoczyć.

Zabezpieczenia te są możliwe do ominięcia, przykładowo – w przypadku, gdy możliwe jest przeczytanie pamięci programu, to istnieje możliwość przystosowania kodu złośliwego programu (tzw. exploita), który przejmie kontrolę nad procesem, często z uprawnieniami systemowymi w przypadku wysoko uprawnionego procesu, lub błędu w kodzie systemu operacyjnego.

Możliwe jest również programowanie „Return Oriented Programming,” w którym znajduje się tak zwane gadżety w programie i ustawia się za ich pomocą rejestry w pamięci, a następnie wykonuje odwołanie do systemu. Dzięki temu, wykorzystuje się już istniejący kod w programie.

Podatności przy użyciu Buffer Overflow często nazywane są tak zwanymi podatnościami dnia zerowego (0 day) - gdy podatność zostanie ujawniona na świat, w przypadku braku łatki.

W celu zabezpieczenia systemów przed atakami z wykorzystaniem bufora przepełnienia, istnieje kilka skutecznych środków zaradczych. Jednym z najważniejszych jest stosowanie technik bezpiecznego programowania, takich jak sprawdzanie granic bufora i unikanie niebezpiecznych funkcji.

### Podsumowanie

Ataki z wykorzystaniem Buffer Overflow stanowią poważne zagrożenie dla bezpieczeństwa systemów informatycznych.  
  
Jednakże, świadomość tych zagrożeń oraz odpowiednie środki obrony mogą pomóc zminimalizować ryzyko i zwiększyć odporność systemów na tego typu ataki. Warto inwestować w edukację programistów oraz w narzędzia i techniki, które mogą pomóc w identyfikowaniu i usuwaniu podatności związanych z przepełnieniem bufora

Źródło:  
Wiedza własna

Krystian Bajno 18530

WIT