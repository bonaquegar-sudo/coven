// Block-pixel wordmark. Small: SVG tiles (sidebar). `big`: hero, outlined block bars with a 3D outline offset and pixel animation.
const SMALL: Record<string, string[]> = {
  "*": ["..###..", ".#####.", "##...##", "##...##", ".#####.", "..###.."], // hex nut
  C: [".####", "#....", "#....", "#....", "#....", ".####"],
  O: [".###.", "#...#", "#...#", "#...#", "#...#", ".###."],
  V: ["#...#", "#...#", "#...#", "#...#", ".#.#.", "..#.."],
  E: ["#####", "#....", "####.", "#....", "#....", "#####"],
  N: ["#...#", "##..#", "#.#.#", "#..##", "#...#", "#...#"],
};
// Claude Code-style block font: 5 rows, horizontal runs drawn as one bar.
const BIG: Record<string, string[]> = {
  "*": ["..####..", ".##..##.", "##....##", ".##..##.", "..####.."], // hex nut
  C: ["######", "##....", "##....", "##....", "######"],
  O: ["######", "##..##", "##..##", "##..##", "######"],
  V: ["##..##", "##..##", "##..##", ".####.", "..##.."],
  E: ["######", "##....", "#####.", "##....", "######"],
  N: ["##..##", "###.##", "######", "##.###", "##..##"],
};

type Props = { text?: string; gear?: boolean; spin?: boolean; big?: boolean; cell?: number; className?: string };

export default function PixelLogo({ text = "COVEN", gear = true, spin = false, big = false, cell = 10, className = "" }: Props) {
  const font = big ? BIG : SMALL;
  const chars = gear ? ["*", " ", ...text] : [...text];
  let x0 = 0;
  const glyphs = chars.map((ch) => {
    const rows = font[ch] ?? ["."]; // unknown/space = one blank column
    const cells: [number, number][] = [];
    rows.forEach((row, y) => [...row].forEach((c, x) => c === "#" && cells.push([x0 + x, y])));
    x0 += rows[0].length + 1;
    return { ch, cells };
  });
  const rows = font.C.length;
  const cols = x0 - 1;

  if (big) {
    const ch = cell * 1.3; // blocks a bit taller than wide
    const bars: [number, number, number][] = []; // x, y, length of each horizontal run
    glyphs.forEach(({ cells }) => cells.forEach(([x, y]) => {
      const last = bars[bars.length - 1];
      if (last && last[1] === y && last[0] + last[2] === x) last[2]++;
      else bars.push([x, y, 1]);
    }));
    const d = cell * 0.45; // 3D: outline copy offset down-right, peeking out as parallel lines
    const W = cols * cell + d + 2, H = rows * ch + d + 2;
    return (
      <svg viewBox={`-1 -1 ${W} ${H}`} width={W} height={H} className={`logo-big ${className}`} role="img" aria-label={text}>
        <g transform={`translate(${d} ${d})`} fill="none" stroke="var(--color-logo)" strokeOpacity={0.6} strokeWidth={1.5}>
          {bars.map(([x, y, n]) => <rect key={`${x},${y}`} x={x * cell} y={y * ch} width={n * cell} height={ch} />)}
        </g>
        {bars.map(([x, y, n]) => (
          // build-in sweeps left to right with a little per-bar jitter; the glint runs diagonally
          <rect key={`${x},${y}`} className="px" x={x * cell} y={y * ch} width={n * cell} height={ch}
                style={{ animationDelay: `${x * 30 + ((x * 7 + y * 13) % 5) * 50}ms, ${(x + y) * 25 + 1600}ms` }} />
        ))}
      </svg>
    );
  }
  const w = cols * cell;
  const h = rows * cell;
  return (
    <svg viewBox={`0 0 ${w} ${h}`} width={w} height={h} className={className} role="img" aria-label={text}>
      {glyphs.map(({ ch, cells }, i) => (
        <g key={i} className={ch === "*" ? `logo-gear ${spin ? "is-spinning" : ""}` : undefined}>
          {cells.map(([x, y]) => (
            <rect key={`${x},${y}`} x={x * cell} y={y * cell} width={cell} height={cell} fill="var(--color-logo)"
                  stroke="var(--color-logo-grid)" strokeWidth={Math.max(cell / 20, 0.4)} />
          ))}
        </g>
      ))}
    </svg>
  );
}
