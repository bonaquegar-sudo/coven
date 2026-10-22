// Block-pixel wordmark: filled tiles plus a double outline offset down-right (Claude Code banner style).
const GLYPHS: Record<string, string[]> = {
  "*": ["#.##.#", ".####.", "##..##", "##..##", ".####.", "#.##.#"], // ASCII gear
  C: [".####", "#....", "#....", "#....", "#....", ".####"],
  O: [".###.", "#...#", "#...#", "#...#", "#...#", ".###."],
  V: ["#...#", "#...#", "#...#", "#...#", ".#.#.", "..#.."],
  E: ["#####", "#....", "####.", "#....", "#....", "#####"],
  N: ["#...#", "##..#", "#.#.#", "#..##", "#...#", "#...#"],
};

type Props = { text?: string; gear?: boolean; spin?: boolean; cell?: number; className?: string };

export default function PixelLogo({ text = "COVEN", gear = true, spin = false, cell = 10, className = "" }: Props) {
  const chars = gear ? ["*", " ", ...text] : [...text];
  let x0 = 0;
  const glyphs = chars.map((ch) => {
    const rows = GLYPHS[ch] ?? ["."]; // unknown/space = one blank column
    const cells: [number, number][] = [];
    rows.forEach((row, y) => [...row].forEach((c, x) => c === "#" && cells.push([x0 + x, y])));
    x0 += rows[0].length + 1;
    return { ch, cells };
  });
  const width = x0 - 1;

  const outline = (cells: [number, number][], d: number) => {
    const on = new Set(cells.map(([x, y]) => `${x},${y}`));
    const has = (x: number, y: number) => on.has(`${x},${y}`);
    const seg = (a: number, b: number, c: number, e: number) => `M${a * cell + d} ${b * cell + d}L${c * cell + d} ${e * cell + d}`;
    return cells
      .map(([x, y]) =>
        [
          !has(x, y - 1) && seg(x, y, x + 1, y),
          !has(x, y + 1) && seg(x, y + 1, x + 1, y + 1),
          !has(x - 1, y) && seg(x, y, x, y + 1),
          !has(x + 1, y) && seg(x + 1, y, x + 1, y + 1),
        ].filter(Boolean).join(""),
      )
      .join("");
  };

  const w = width * cell + cell * 0.6;
  const h = 6 * cell + cell * 0.6;
  return (
    <svg viewBox={`0 0 ${w} ${h}`} width={w} height={h} className={className} role="img" aria-label={text}>
      {glyphs.map(({ ch, cells }, i) => (
        <g key={i} className={ch === "*" ? `logo-gear ${spin ? "is-spinning" : ""}` : undefined}>
          <g fill="none" stroke="var(--color-logo)" strokeWidth={Math.max(cell / 12, 0.6)} opacity={0.85}>
            <path d={outline(cells, cell * 0.3)} />
            <path d={outline(cells, cell * 0.5)} />
          </g>
          {cells.map(([x, y]) => (
            <rect key={`${x},${y}`} x={x * cell} y={y * cell} width={cell} height={cell} fill="var(--color-logo)"
                  stroke="var(--color-logo-grid)" strokeWidth={Math.max(cell / 20, 0.4)} />
          ))}
        </g>
      ))}
    </svg>
  );
}
