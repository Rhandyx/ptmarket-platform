import { Button } from "../../components/ui/Button";
import { logoutAction } from "./actions";

/** "Terminar sessão": form POST (funciona sem JavaScript). */
export function LogoutForm({ label = "Terminar sessão", variant = "secondary" }: { label?: string; variant?: "secondary" | "ghost" }) {
  return (
    <form action={logoutAction}>
      <Button type="submit" variant={variant}>
        {label}
      </Button>
    </form>
  );
}
