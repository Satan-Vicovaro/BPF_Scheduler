// --- 1. CONFIGURATION (Do not change this often) ---
#let latex_report(
  title: "",
  author: "",
  date: datetime.today().display(),
  body
) = {
  set document(title: title, author: author)
  // Font: Prefers "New Computer Modern" (Standard LaTeX), falls back to Times
  set text(font: ("New Computer Modern", "Times New Roman"), size: 11pt, lang: "pl")
  set par(justify: true, leading: 0.65em, first-line-indent: 1.5em)
  show par: set block(spacing: 0.65em)

  // Headings: Numbered and Bold
  set heading(numbering: "1.1")
  show heading: it => {
    set text(weight: "bold", fill: black)
    block(above: 2em, below: 1em, it)
  }

  // Page numbers at bottom center
  set page(
    footer: context align(center, counter(page).display("1"))
  )

  // Title Page
  page(numbering: none, footer: none)[
    #v(3fr)
    #align(center)[
      #text(size: 2em, weight: "bold", title) \
      #v(1.5em)
      #text(size: 1.2em, author) \
      #v(0.5em)
      #date
    ]
    #v(4fr)
  ]
  counter(page).update(1)

  body
}

// Custom formal note box
#let note(title: "Note", content) = {
  pad(y: 1em, block(
    fill: luma(250), stroke: 0.5pt + black, 
    inset: 1em, width: 100%, radius: 0pt, breakable: true,
    [*#title:* #content]
  ))
}

// --- 2. DOCUMENT CONTENT ---
#show: latex_report.with(
  title: text(
  hyphenate: false,
  "Sprawozdanie z projektu na Oprogramowanie Systemowe"),
  author: "Łukasz Kołakowski 198000",
  date: "28 Stycznia 2026"
)


= Opis środowiska 
  Planista został wykonany na system operacyjny Linux, wersja jądra wynosi 6.14 i
  tylko na tej wersji będzie działać mój planista. Dystrybucją Linuxa na,
  której robiłem projekt jest Linux Mint, nie jest to wymagane.
  Najlepiej by dystrybucja miała interfejs graficzny, co pozwoli na łatwe zauważenie działania planisty.

= Zastosowane rozwiązanie techniczne
  Implementacja _schedulera_ nastąpiła przy pomocy frameworku eBPF wraz z dedykowanym rozszerzeniem do kernela
  _sched_ext_ #footnote(link("https://github.com/sched-ext/scx")).
  Kod napisany jest w C, przy pomocy libbpf #footnote(link("https://github.com/libbpf/libbpf")), biblioteki implementującej BPF.
  Jest ona nowsza od BCC #footnote(link("https://github.com/iovisor/bcc")) i pozwala na większą ingerencję w struktury jądra.
  BCC jest dobry do monitorowania, nasłuchiwania i zbierania informacji.
  Libbpf rozszerza te możliwości i ułatwia np. wyżej wspomniane dodawanie implementacji planisty, wymiana funkcjonalności systemu itd. .

= Co udało się zrealizować
Udało mi się na początku zaimplementować minimalnego planistę jako test czy,
_sched_ext_ działa jak powinien. Implementuje on politykę typu _round robin_
ze zmienną porcją przydzielanego czasu. Kolejka jest wspólna dla wszystkich rdzeni procesora.
Po czym postarałem się rozszerzyć planistę; dodatkowo zapisuje 
i wypisuje użytkownikowi informacje o procesach, którym przedziela czas.
Zapisuje statystyki takie jak:
- przydzielony czas;
- pid;
- krótka nazwa procesu;
- łączny czas czekania na czas procesora;
- maksymalny czas czekania.

Zobaczyłem jak zachowuje się planista, jeżeli przydzielimy bardzo kawałek czasu (sekundy, setne sekund)
lub jak będzie on bardzo mały (nanosekudny).

Dodatkowo chciałem zobaczyć czy da się zagłodzić niechciane zadania, celowo nie przydzielając im czasu procesora.



= Architektura projektu
Projekt składa się praktycznie z dwóch plików, jeden zawiera kod wrzucany do jądra,
realizujący wybraną politykę planisty. Drugi jest programem w _User space_, który  załącza planistę, a potem wypisuje użytkownikowi informacje o procesach, którym przedzielany jest czas.

#pagebreak()
Kod jądra:
== Zmienne, stałe i marka
#block(
  fill: luma(240), // Light grey background
  inset: 10pt,     // Space between code and edge
  radius: 4pt,     // Rounded corners
  width: 100%,     // Full page width
)[
#set text(size: 9pt)
```C
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// there is some problem with headers:
// vmlinux.h is kinda weird with that
extern s32 scx_bpf_create_dsq(u64 dsq_id, s32 node_id) __ksym;
extern void scx_bpf_dsq_insert(struct task_struct *p, u64 dsq_id, u64 slice,
                               u64 enq_flags) __ksym;
extern void scx_bpf_dispatch(struct task_struct *p, u64 dsq_id, u64 slice,
                             u64 enq_flags) __ksym;
extern void scx_bpf_consume(u64 dsq_id) __ksym;
extern s32 scx_bpf_dsq_nr_queued(u64 dsq_id) __ksym;
extern bool scx_bpf_dsq_move_to_local(u64 dsq_id) __ksym;
extern void scx_bpf_kick_cpu(s32 cpu, u64 flags) __ksym;
// extern __u64 (*const bpf_ktime_get_boot_ns)(void) = (void *)125;

// Define a shared Dispatch Queue (DSQ) ID
#define SHARED_DSQ_ID 2  // normal
#define PARKING_DSQ_ID 3 // for tasks we hate and don't want to run
#define DELAY_NS 1000000000ULL
char forbidden_name[6] = "hello";
int time_to_unpark = 0;

#define BPF_STRUCT_OPS(name, args...)                                          \
  SEC("struct_ops/" #name) BPF_PROG(name, ##args)

#define BPF_STRUCT_OPS_SLEEPABLE(name, args...)                                \
  SEC("struct_ops.s/" #name)                                                   \
  BPF_PROG(name, ##args)

typedef struct global_sched_data {
  int call_function_counter;
  unsigned int last_used_index;
} global_sched_data;

typedef struct task_stats_ext {
  int call_function_counter;
  int last_used_index;

  u64 slice;
  int pid;
  int recent_used_cpu;
  long unsigned int last_switch_count;
  long unsigned int last_switch_time;

  char comm[16];
  u64 total_wait_ns;
  u64 max_wait_ns;
  u64 start_wait_ns;
  u64 wait_count;
} task_stats_ext;

// Array map definition
struct {
  __uint(type, 29); // <- this is 	BPF_MAP_TYPE_TASK_STORAGE
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, int);
  __type(value, task_stats_ext);
} task_storage SEC(".maps");

struct parking_lot {
  struct bpf_timer timer;
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, int);
  __type(value, struct parking_lot);

} timer_map SEC(".maps");
}
```
]
W tej części deklarujemy wszystkie zmienne z jakich będziemy korzystać.
Był problem z funkcjami typu _scx_bpf\.\.\._ dlatego funkcje kernela są zadeklarowane u góry dodatkowo.
Najważniejszym structem jest _task_stats_ext_, odpowiada on za dodatkową logikę naszego planisty.
Nie jesteśmy w stanie zmieniać wartości zmiennych w jądrze, więc na potrzeby planisty eBPF dodali specjalną strukturę _BPF_MAP_TYPE_STORAGE_, w której możemy przypisywać do każdego wątku
dodatkowe parametry, na podstawie których będziemy dysponować czasem procesora.
== 
#block(
  fill: luma(240), // Light grey background
  inset: 10pt,     // Space between code and edge
  radius: 4pt,     // Rounded corners
  width: 100%,     // Full page width
)[```C
// Initialize the scheduler by creating a shared dispatch queue (DSQ)
s32 BPF_STRUCT_OPS_SLEEPABLE(sched_init) {
  // All scx_ functions come from vmlinux.h
  scx_bpf_create_dsq(SHARED_DSQ_ID, -1);
  scx_bpf_create_dsq(PARKING_DSQ_ID, -1); // second queue

  return 0;
}

// Enqueue a task to the shared DSQ that wants to run,
// dispatching it with a time slice
int BPF_STRUCT_OPS(sched_enqueue, struct task_struct *p, u64 enq_flags) {

  u64 slice = 0u / scx_bpf_dsq_nr_queued(SHARED_DSQ_ID);

  if (p->pid == 6070 ||
      __builtin_memcmp(p->comm, forbidden_name, sizeof(forbidden_name)) == 0) {
    slice = 67;
    // scx_bpf_dsq_insert(p, SHARED_DSQ_ID, slice, enq_flags);
    bpf_printk("Parking %s for %d seconds...\n", forbidden_name,
               DELAY_NS / 1000000000);

    int key = 0;
    struct parking_lot *val = bpf_map_lookup_elem(&timer_map, &key);
    if (val) {
      bpf_timer_init(&val->timer, &timer_map, 1);
      bpf_timer_set_callback(&val->timer, timer_cb);
      bpf_timer_start(&val->timer, DELAY_NS, 0);
    }
    scx_bpf_dsq_insert(p, PARKING_DSQ_ID, slice, enq_flags);

  } else if (__builtin_memcmp(p->comm, forbidden_name,
                              sizeof(forbidden_name)) == 0) {
  } else {
    // Calculate the time slice for the task based on the number of tasks in
    // the queue
    slice = 50000000u; // (scx_bpf_dsq_nr_queued(SHARED_DSQ_ID) + 2);
    scx_bpf_dsq_insert(p, SHARED_DSQ_ID, slice, enq_flags);
  }

  // ------------- stats for listener ---------------

  // global sched data
  static global_sched_data g_sched_data = {0, 0};

  // reference to  task map
  task_stats_ext *stats = bpf_task_storage_get(&task_storage, p, NULL,
                                               BPF_LOCAL_STORAGE_GET_F_CREATE);

  // stats
  if (stats) {
    stats->call_function_counter = g_sched_data.call_function_counter;
    stats->slice = slice;
    stats->pid = p->pid;
    stats->recent_used_cpu = p->recent_used_cpu;
    stats->last_switch_count = p->last_switch_count;
    stats->last_switch_time = p->last_switch_time;
    stats->start_wait_ns = bpf_ktime_get_boot_ns(); // now
    bpf_probe_read_kernel_str(stats->comm, sizeof(stats->comm), p->comm);
  }
  return 0;
}

// Dispatch a task from the shared DSQ to a CPU,
int BPF_STRUCT_OPS(sched_dispatch, s32 cpu, struct task_struct *prev) {
  if (time_to_unpark == 1) {
    bpf_printk("Dispaching from Parking");

    if (scx_bpf_dsq_move_to_local(PARKING_DSQ_ID)) {
      time_to_unpark = 0;
      return 0;
    }
  }
  scx_bpf_dsq_move_to_local(
      SHARED_DSQ_ID); // <- this function is different in 6.12 and 6.12
  return 0;
}

```]
To jest serce całego projektu, cały planista składa się z 3 funkcji: 
- inicjalizacja kolejki
- wrzucanie zadań do kolejki
- przerzucanie zadań z kolejki na procesor
Jest to minimalna liczba funkcji, które trzeba zaimplementować.

W inicjalizacji tworzymy dwie kolejki, są to _schared dispatch queue_, czyli wspólna kolejka na wszystkie procesory. Tworzymy je dwie, jedna dla normalnych procesów, druga dla procesów które będziemy chcieli intencjonalnie głodzić.

Do *sched_enqueue* trafiają gotowe zadania do uruchomienia na procesorze, naszym zadaniem jest 
przydzielenie im czasu i wywołanie funkcji *scx_bpf_dsq_insert*. Zadania które chcemy by
wykonywały się normalnie trafią do kolejki _SHARED_DSQ_ID_. Jeżeli nasze zadanie ma dane _pid_
lub nazwę to, zostaną wrzucone do drugiej kojeki _PARKING_DSQ_ID_, jak nazwa wskazuje działa jak
parking, na który będą trafiać zadania, które odstawiamy na bok na by sobie poczekały 
(na tyle długo na ile pozwali nam jądro) zanim dostaną czas procesora.

Zadanie trafia na procesor w funkcji *sched_dispatch*, warto zauważyć, że nie mamy tutaj
dostępu do zadania, które zostanie wrzucone. Mamy dostęp tylko do zadania wywłaszczonego
i dla niego możemy ustawić parametry. Funkcja *scx_bpf_dsq_move_to_local* weźmie zadania
znajdujące się na szczycie kolejki i przypisze je do procesora, mamy tutaj możliwość
sprecyzowania z której kolejki dostarczymy zadanie.

== Głodzenie niechcianych zadań
Głodzenie zadań polega na przypisaniu zadań do wyżej wymienionej _PARKING_DSQ_ID_, 
nie można pominąć zadań przy przydziale czasu procesora, ponieważ planista
zaimplementowany przy pomocy _sched_ext_ jest sprawdzany, czy nie jest wadliwy. Planista musi
przydzielić czas procesora w ciągu 30s (można te wartość zmniejszyć) od czasu 
oczekiwania. Jeżeli minie wymieniony wyżej okres czasu, planista zostanie wyrzucony z pamięci i zostanie na nowo uruchomiony standardowy planista oparty o drzewo czerwono czarne.

Gdy zadnie trafi do rezerwowej kolejki zostanie uruchomiony licznik, który po czasie 
(w moim przypadku 1 sekunda) ustawi flagę, która spowoduje, że przy najbliższej okazji procesorowi
zostanie przydzielony czas z tej rezerwowej kolejki.

== Kod po stronie użytkownika

#block(
  fill: luma(240), // Light grey background
  inset: 10pt,     // Space between code and edge
  radius: 4pt,     // Rounded corners
  width: 100%,     // Full page width
)[```C
#include "selective.skel.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/resource.h>
#include <unistd.h>

typedef unsigned long long u64;
typedef unsigned int u32;

typedef struct task_stats_ext {
    int call_function_counter;
    int last_used_index;

    u64 slice;
    int pid;
    int recent_used_cpu;
    long unsigned int last_switch_count;
    long unsigned int last_switch_time;

    // u64 voluntary_switch_count;
    // u64 involuntary_switch_count;

    u64 exec_max;

    u64 total_wait_ns;
    u64 max_wait_ns;
    u64 start_wait_ns;
    u64 wait_count;
} task_stats_ext;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args)
{
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{

    struct selective_bpf *skel;
    int err;

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* Open BPF application */
    skel = selective_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* ensure BPF program only handles write() syscalls from our process */
    // skel->bss->my_pid = getpid();
    /* Load & verify BPF programs */
    err = selective_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    printf("attaching sched");
    struct bpf_link *link = bpf_map__attach_struct_ops(skel->maps.sched_ops);
    if (!link) {
        fprintf(stderr, "Failed to register scheduler: %d\n", -errno);
        goto cleanup;
    }
    skel->links.sched_ops = link;

    // int map_fd = bpf_map__fd(skel->maps.task_storage);

    /* Attach tracepoint handler */
    err = selective_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("Successfully started! The selective scheduler \n");

    struct bpf_link *iter_link =
        bpf_program__attach_iter(skel->progs.dump_task_stats, NULL);

    if (!iter_link) {
        fprintf(stderr, "Failed to attach iter_link\n");
        goto cleanup;
    }

    fprintf(stderr, ".");
    while (true) {

        int iter_fd = bpf_iter_create(bpf_link__fd(iter_link));
        if (iter_fd < 0) {
            fprintf(stderr, "Failed to create iterator File Descriptor\n");
            break;
        }

        char buf[8192];
        int n = 0;
        fprintf(stderr, ".");
        while ((n = read(iter_fd, buf, sizeof(buf))) > 0) {
            write(STDOUT_FILENO, buf, n);
        }
        close(iter_fd);
        sleep(10);
    }

cleanup:
    selective_bpf__destroy(skel);
    return -err;
}

```]
Po stronie użytkownika kod nie jest ciekawy, zawiera on inicjalizację programu, próbuje 
załadować 
naszego planistę, potem próbuje uzyskać dostęp do pliku, w którym zapisywane będą 
dodatkowe 
informacje o zadaniach. Potem w pętli okresowo co 10 sekund odczytuje zawartość pliku, i wypisuje ją użytkownikowi.

Warty wspomnienia jest ten mechanizm komunikacji pomiędzy programem użytkownikiem a programem
jądra. Programy eBPF jeżeli chcą zapisać jakieś informacje muszą korzystać w własnych
dedykowanych struktur, są one zapisywane jako plik zapisany w pamięci RAM. Nie mogą nasze 
funkcje też wywoływać funkcji typu _malloc()_. Struktury danych jakie eBPF oferuje są 
różnorodne, ale zawiera szereg ograniczeń.
Nasz program korzysta z dedykowanej struktury danych typu
_BPF_MAP_TYPE_TASK_STORAGE_, która tworzy mapę typu _pid_ -> _task_stats_ext_. Program użytkownika
może ją odczytać, ale nie została ta struktura do tego stworzona, więc by było to możliwe 
trzeba
utworzyć specjalny iterator po stronie kernela, który za nas będzie po niej przechodzić, 
a my będziemy na bieżąco z czytywać i zapisywać informacje u siebie.

#block(
  fill: luma(240), // Light grey background
  inset: 10pt,     // Space between code and edge
  radius: 4pt,     // Rounded corners
  width: 100%,     // Full page width
)[```C
// helper for getting task_storage
SEC("iter/task")
int dump_task_stats(struct bpf_iter__task *ctx) {
  struct seq_file *seq = ctx->meta->seq;
  struct task_struct *task = ctx->task;
  if (!task)
    return 0;

  task_stats_ext *stats = bpf_task_storage_get(&task_storage, task, 0, 0);
  if (!stats)
    return 0;

  if (stats->pid == 0) {
    return 0;
  }

  if (stats->pid == 2137 || __builtin_memcmp(stats->comm, forbidden_name,
                                             sizeof(forbidden_name)) == 0) {

    BPF_SEQ_PRINTF(seq,
                   "------- Name: %-16s Pid: %-8d slice: %-10lld "
                   "max_wait(ms): %-10lld "
                   "total_wait(ms): %-10lld"
                   "wait_count: %-10lld\n",
                   stats->sched excomm, stats->pid, stats->slice,
                   (stats->max_wait_ns) / 1000000,
                   stats->total_wait_ns / 1000000, stats->wait_count);
    return 0;
  }

  BPF_SEQ_PRINTF(seq,
                 "Name: %-16s Pid: %-6d slice: %-10lld max_wait(ms): %-5lld "
                 "total_wait(ms): %-5lld"
                 "wait_count: %-4lld\n",
                 stats->comm, stats->pid, stats->slice,
                 (stats->max_wait_ns) / 1000000, stats->total_wait_ns / 1000000,
                 stats->wait_count);
  return 0;
};
```]

= Kompilacja programu
== Wymagania systemowe
- *Wersja jądra:* **6.14** (wersje 6.13 oraz 6.12 wymagają drobnych poprawek w kodzie ze względu na zmiany w nazewnictwie funkcji).
- *Kompilator:* Clang z obsługą BPF.
- *Narzędzia BPF:*
```bash
  sudo apt install clang llvm libelf-dev libz-dev
```
- Najnowsza biblioteka libbpf:

```bash
  git clone https://github.com/libbpf/libbpf.git
  cd libbpf/src && make
```

== Budowanie i uruchamianie
+ Umieść bibliotekę libbpf w głównym folderze (root) tego repozytorium.
+ Wygeneruj nagłówki jądra Linux:
  ```bash
    cd scheduler_ext/selective/
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
  ```  
+ Skompiluj kod jądra (eBPF):
  ```bash
    clang -target bpf -g -O2 -c selective.bpf.c -o selective.bpf.o -I.
  ``` 
+ Wygeneruj szkielet (skeleton) dla programu w przestrzeni użytkownika:
  ```bash
    bpftool gen skeleton selective.bpf.o > selective.skel.h
  ```
+ Skompiluj program użytkownika:
  ```bash
    clang -g -O2 -Wall listener.c -o listener ./../../libbpf/src/libbpf.a -lelf -lz
  ```
+ Uruchom planistę:
  ```bash
    ./listener
  ```

#pagebreak()
= Działanie programu
Program działa od razu po uruchomieniu i zamienia aktualnie działającego planistę na naszego.
Działanie programu będzie powiedziane opisowo ze względu na to, że efekty działania widać 
najlepiej poprzez obserwację interfejsu graficznego, co jest ciężkie do pokazania w pliku _pdf_.
== Normalne działanie programu
Porcja czasu jest wyliczana następująco:
```C
    slice = 50000000u / (scx_bpf_dsq_nr_queued(SHARED_DSQ_ID) + 1);
```
Przydzielony czas to 50 milisekund podzielone przez liczbę aktualnie czekających procesów. 
Procesor na którym wykonywane są obliczenia to _Intel Core i5-1240P_ posiadający 16 rdzeni.
Przed włączenie planisty zostało uruchomione 8 procesów za pomocą komendy _stress_.
Planista działał przez 60 sekund.
#figure(
  image("normal.png", width: 100%),
  caption: [Przedstawia output z statystykami na temat działających programów, zbierane przez 60 sekund]
)
- Name - Krótka nazwa procesu.
- Pid - Identyfikator procesu (_Process IDentifier_).
- slice - Czas przydzielony zadaniu w nanosekundach.
- max_wait - Największy czas oczekiwania w kolejce.
- total_wait - Łączny czas oczekiwana w kolejce, liczone od startu programu.
- wait_count - Liczba mówiąca ile razy proces był w kolejce.
- slice sum - Suma przydzielonych czasów do zadania, liczone od startu programu.
Jeżeli chcemy wyliczyć efektywność naszego planisty wystarczy podzielić _slice_sum_ przez czas 
jaki program działał, w naszym przypadku 60s. Jest to wzór przybliżony wzór nieuwzględniający wywłaszczania, ale na potrzeby tego sprawozdania jest wystarczający.

$ "efektywność" = "slice sum" / "czas działania programu"  = 94% $


== Działanie dla dużego _slice'a_
Jeżeli ustawimy kwant czasu procesora na wartość 1 sekundy, po włączeniu planisty nic się
nie dzieje. Wszystkie elementy interfejsu są responsywne i można korzystać z systemu. Wynika to 
z faktu, że procesy systemowe i graficzne na Linuxie nie działają ciągle, tylko okresowo lub 
czekają na akcję użytkownika, dobrowolnie oddają czas. Komputer staje się nie użyteczny jeżeli 
włączymy programy, które nie oddają dobrowolnie czasu. Jeżeli uruchomimy komendę: 
```bash
  steress -c 16
```
utworzymy 16 procesów wykonywających w pętli obliczenia. Spowoduje to, że wszystkie rdzenie procesora
na moim komputerze zostaną zajęte i wtedy system operacyjny się zawiesi.

#figure(
  image("big_slice.png", width: 100%),
  caption: [Przedstawia output z stysytkami, dla stałej porcji 1s, przez 60 sekund działania programu]
)
$ "efektywność" = 100% $
Nasz wzór jest trochę zbyt optymistyczny _slice sum_ mówi ile czasu my chcieliśmy dać
procesowi nie uwzględniają czasu czekania i czasu potrzebnego na wywłaszczenie procesu, 
ale po uwzględnieniu tych czynników efektywność byłaby rzędu ponad 99%. 

Wydaje się, że duże porcje czasu są lepsze niż w normalnym przypadku, jednakże widać, że 
inne procesy musiały czekać całą sekundę, z tego wynika brak responsywności interfejsu 
graficznego. Niektóre procesy były niejako zagładzane, ponieważ za dużo czasu spędzały w 
kolejce a praca jaką musiały wykonać pewnie nie przekraczały parunastu milisekund.

== Działanie dla bardzo małego _slice'a_
Jeżeli ustawimy przydział czasu na bardzo mały rzędu nanosekund, system zostanie reaktywny bardzo
długo.

#figure(
  image("sensowny mały.png", width: 100%),
  caption: [Stała porcja czasu 10 mikrosekund, przez 60 sekund działania programu]
)
10 mikrosekund jest to wystarczająco dużo czasu by zaszło przełączenie kontekstu, ale 
mimo to _slice sum_ daje zaniżone wyniki, ponieważ przełączenie kontekstu nie nastąpi 
od razu, a w odpowiednim momencie zwanym _preemption point_.
W naszym przypadku wydajniejsze będzie zobaczenie ile czasu spędziliśmy czekając w  
stosunku 
do czasu jaki proces miał pracować:

$ "efektywność" = 49% $

Łatwo zauważyć, że dla małej porcji czasu nasz system zamiast dać zadaniom pracować, skupia się na przełączaniu wątków co zmniejsza efektywność pracy komputera.

#pagebreak()
== Zagładzanie zadań
Zaimplementowane zostało intencjonalne zagładzanie niechcianych zadań, na podstawie
jego pid lub krótkiej nazwy. Wyżej opisany mechanizm działa jak należy, i dla testowego 
programu wypisującego _"Hello world"_ w pętli, program jest w stanie w swoim kawałku czasu wyświetlić około 100 napisów na możliwie najkrótszym przydziale czasu procesora. 
Ujawnia się tutaj tzw. _punkt wywłaszczania_. Proces na Linuxie nie zostanie wywłaszczony 
od razu, gdy jego czas minie. Zostanie to zrobione przy najbliższej możliwej okazji w
odpowiednim miejscu:
- Powrocie do przestrzeni użytkownika.
- Powrocie do przestrzeni jądra.
#figure(
  image("zagładzany.png", width: 100%),
  caption: [Wynik programu z zaznaczonym zagładzanym procesem _hello_, czas działania: 60 sekund]
)


= Problemy na jakie natrafiłem 

== Rozbieżność wersji
W przykładach nazwa funkcji do przełączenia zadań na procesorze nazywa się: 
```
  scx_bpf_consume(u64 dsq_id)
```

a w wersji jądra 6.14 nazwa została zmieniona na: 
```
  scx_bpf_dsq_move_to_local(u64 dsq_id)
```
by znaleźć to trzeba zajrzeć do dokumentacji dokładnej wersji i
zobaczyć jak zmieniła się nazwa funkcji: 
#link("https://github.com/torvalds/linux/blob/v6.14/kernel/sched/ext.c#L6749").
Trzeba mieć na uwadze, że jądro Linuxa jest dynamicznie rozwijane i dokumentacja
nie nadąża lub jest może być nieaktualna.

== Output eBPF

Oto typowy output błędu przy kompilacji za pomocą eBPF:

```
libbpf: prog 'sched_running': BPF program load failed: -EACCES
libbpf: prog 'sched_running': -- BEGIN PROG LOAD LOG --
0: R1=ctx() R10=fp0
; int BPF_STRUCT_OPS(sched_running, struct task_struct *p) { @ selective.bpf.c:158
0: (79) r7 = *(u64 *)(r1 +0)
func 'running' arg0 has btf_id 86 type STRUCT 'task_struct'
1: R1=ctx() R7_w=trusted_ptr_task_struct()
; task_stats_ext *stats = bpf_task_storage_get(&task_storage, p, NULL, @ selective.bpf.c:160
1: (18) r1 = 0xffff8e975abf8400       ; R1_w=map_ptr(map=task_storage,ks=4,vs=88)
3: (bf) r2 = r7                       ; R2_w=trusted_ptr_task_struct() R7_w=trusted_ptr_task_struct()
4: (b7) r3 = 0                        ; R3_w=0
5: (b7) r4 = 1                        ; R4_w=1
6: (85) call bpf_task_storage_get#156         ; R0_w=map_value_or_null(id=1,map=task_storage,ks=4,vs=88)
7: (bf) r6 = r0                       ; R0_w=map_value_or_null(id=1,map=task_storage,ks=4,vs=88) R6_w=map_value_or_null(id=1,map=task_storag
e,ks=4,vs=88)
; if (!stats) { @ selective.bpf.c:163
8: (15) if r6 == 0x0 goto pc+18       ; R6_w=map_value(map=task_storage,ks=4,vs=88)
9: (b7) r1 = 23                       ; R1_w=23
; p->on_cpu = 23; @ selective.bpf.c:166
10: (63) *(u32 *)(r7 +52) = r1
processed 10 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
-- END PROG LOAD LOG --
libbpf: prog 'sched_running': failed to load: -EACCES
libbpf: failed to load object 'selective_bpf'
libbpf: failed to load BPF skeleton 'selective_bpf': -EACCES
Failed to load and verify BPF skeleton
```

Ciężko jest za pierwszym razem zrozumieć jaki jest błąd. Występuje on
po poprawnej kompilacji programu, więc nie jest to błąd składniowy. Błąd wynika
z niezrozumienia jakiejś własności programów eBPF. Błąd _EACCES_ może oznaczać wiele
rzeczy, w wielu przypadkach błąd zwracany przez eBPF nie jest przydatny w debugowaniu. Wymaga dogłębnego przeanalizowania co poszło nie tak i dogłębnej wiedzy o tym jak działa
eBPF, na co pozwala, a na co nie.
eBPF jest ciągle rozwijany i jak korzysta się z najnowszych technologii, to nie 
wiadomo czy błąd na który się natknąłeś jest twoim brakiem wiedzy, czy bugiem który 
zostanie dopiero załatany

W tym przypadku jednym z rozwiązań jest zapytania chatbota, jego 
odpowiedź nie musi być prawidłowa, ale może nakierować nas na dobry trop. Dla powyższego 
kodu podaje poprawą odpowiedź: 
#image("chatbot.png")

W kodzie chcemy zmienić fragment pamięci należącą do jądra: 
```C
  p->on_cpu = 23; @ selective.bpf.c:166
```
Na co eBPF nie pozwala. Jest to błąd który pojawia się *w trakcie działania programu*.

Ważne w pracowaniu z eBPF jest częste *kompilowanie* i *uruchamianie* programu. Jeżeli 
napiszemy 300 linijek kodu i dostaniemy nic nie mówiący błąd w trakcie trwania procesu, 
nie będziemy wiedzieć gdzie szukać błędu. Ważnym jest by jak najszybciej stworzyć coś 
działającego i w małych porcjach dodawanie linijek kodu, by w razie błędu liczba linijek 
do sprawdzania była relatywnie mała.
== Pomyłki w przykładach?
W przykładach pokazane jest zrobienie wspólnej kolejki na procesy (_schared_dispatch_queue_)
z podaną linijką:
```
    u64 slice = 5000000u / scx_bpf_dsq_nr_queued(SHARED_DSQ_ID);
    scx_bpf_dispatch(p, SHARED_DSQ_ID, slice, enq_flags);
```
_scx_bpf_dsq_nr_queued_, zwraca liczbę procesów aktualnie znajdujących się w kolejce do procesorów.
Problemem jest to, że kolejka może być pusta, co powodowałoby dzielenie przez 0.
Dzielenie przez 0 w programach eBPF nie powoduje wyrzucenia błędu, lecz po prostu wynikiem jest 0.
Powoduje to, że porcja czasu dostarczona do procesu wynosi 0. Nie oznacza to, że proces
nie dostanie czasu procesora, a po prostu zostanie wywłaszczony przy najbliższej możliwej okazji.
Ten błąd jednak nie powoduje żadnych problemów, w trakcie trwania planisty, ale jest to raczej
nie zamierzane. Danie bardzo małego kawałku czasu jest nie efektywne, ale nie powoduje
utraty responsywności komputera, dopóki liczba procesów wymagająca stale czasu procesora
nie jest dużo większa od liczby rdzeni procesora.

Znalazłem to przez przypadek realizując mój projekt. Wypisując dane, które przypisuje 
_scheduler_ zauważyłem, że _slice_ wynosi 0. nie wydaje mi się by miał dla tej wartości 
specjalne własności. Trzeba wiedzieć, że dokumentacja, czy przykłady mogą mieć 
błędy, lub być nie optymalne.


== Skąd wziąć nazwy funkcji?
Jest dokumentacja dotycząca funkcji eBPF od tym linkiem:
#link("https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_STRUCT_OPS/sched_ext_ops/").
Nie jest zbiór funkcji jądra, tyle funkcje do komunikacji z eBPF; nie ma tutaj 
najważniejszych funkcji, które faktycznie umożliwiają komunikację z jądrem w celu 
przydzielenia czasu procesora.
By się tego dowiedzieć trzeba zobaczyć faktyczną implementację: 
#link("https://github.com/torvalds/linux/blob/v6.14/kernel/sched/ext.c"). 
Funkcje są tam dobrze opisane i faktycznie tłumaczą jakie mają zastosowanie.


= Wnioski
Pisanie programów z pomocą eBPF jest zalecaną drogą dodawania funkcjonalności do jądra 
systemu Linux. Nie jest to narzędzie w pełni uniwersalne i ma swoje ograniczenia, ale z 
roku na rok dodawanych jest coraz więcej funkcjonalności.

Problem jest z dokumentacją, często jest ona wybrakowana lub pewne rzeczy zostały 
zmienione pomiędzy poszczególnymi wersjami jądra, i nie jest do udokumentowane. Wyjście  
w razie błędu wygenerowane przez eBPF często
jest nie zrozumiałe i mao pomocne, więc trzeba cofać się do najbliższej działającej 
wersji by nabrać pojęciagdzie leży błąd.

Gdyby nie dedykowane rozszerzenie _sched_ext_ napisanie tego w eBPF byłoby nie możliwe, 
i musiałbym ręcznie dodać planistę do jądra i za każdym razem kompilować całe jądro. Ten
proces byłby o wiele dłuższy i nużący. Jakikolwiek błąd kończył, by się zawieszeniem 
pracy komputera, albo tzw. _kernel panic!_.

Planista działa tak jak powinien, ciekawe było do obserwacji zachowanie systemu pod 
wpływem samemu napisanego planisty. Spędziłem dużo czasu na próbach wyjaśnienia czemu
działa tak, a nie inaczej (na przykład zachowania dla bardzo dużej porcji czasu).



= Literatura i źródła
- Kod źródłowy: #link("https://github.com/Satan-Vicovaro/BPF_Scheduler")
- #link("https://cilium.isovalent.com/hubfs/Learning-eBPF%20-%20Full%20book.pdf")
- #link("https://github.com/torvalds/linux/blob/v6.14/kernel/sched/ext.h")
- #link("https://github.com/parttimenerd/minimal-scheduler?tab=readme-ov-file")
- #link("https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_STRUCT_OPS/sched_ext_ops/")
