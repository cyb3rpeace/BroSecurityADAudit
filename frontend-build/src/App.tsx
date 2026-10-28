import { TooltipProvider } from "@/components/ui/tooltip"
import { Toaster } from "@/components/ui/sonner"
import { AppProvider, useApp } from "@/app-state"
import { Login } from "@/pages/login"
import { Shell } from "@/pages/shell"

function Gate() {
  const { loading, me } = useApp()
  if (loading) {
    return <div className="text-muted-foreground grid min-h-svh place-items-center">BroSec Audit AD</div>
  }
  return me ? <Shell /> : <Login />
}

export default function App() {
  return (
    <TooltipProvider>
      <AppProvider>
        <Gate />
        <Toaster />
      </AppProvider>
    </TooltipProvider>
  )
}
