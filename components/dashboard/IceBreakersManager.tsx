"use client"

import { useState, useEffect, useCallback } from "react"
import { useInstagramSession } from "@/hooks/use-instagram-session"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import { Loader2, Plus, Trash2, Save, RefreshCw } from "lucide-react"
import { toast } from "sonner"

type IceBreakerRow = { id?: string; question: string; response: string }

export function IceBreakersManager() {
    const { userId, isLoading } = useInstagramSession()
    const [breakers, setBreakers] = useState<IceBreakerRow[]>([])
    const [saving, setSaving] = useState(false)
    const [fetching, setFetching] = useState(true)

    const fetchBreakers = useCallback(async (): Promise<IceBreakerRow[] | null> => {
        if (!userId) return null
        try {
            const res = await fetch(`/api/ice-breakers?userId=${userId}`)
            if (!res.ok) {
                console.error(`[IceBreakers] Fetch error: category=HTTP_ERROR status=${res.status}`)
                return null
            }
            const data: unknown = await res.json()
            return Array.isArray(data) ? (data as IceBreakerRow[]) : null
        } catch {
            console.error("[IceBreakers] Fetch error: category=NETWORK_ERROR")
            return null
        }
    }, [userId])

    useEffect(() => {
        let active = true

        void fetchBreakers().then((data) => {
            if (!active) return
            if (data) setBreakers(data)
            setFetching(false)
        })

        return () => {
            active = false
        }
    }, [fetchBreakers])

    const refreshBreakers = async () => {
        const data = await fetchBreakers()
        if (data) setBreakers(data)
        setFetching(false)
    }

    const handleAdd = () => {
        if (breakers.length >= 4) {
            toast.error("Maximum 4 Ice Breakers allowed by Instagram")
            return
        }
        setBreakers([...breakers, { question: "", response: "" }])
    }

    const handleChange = (index: number, field: "question" | "response", value: string) => {
        const newBreakers = [...breakers]
        newBreakers[index] = { ...newBreakers[index], [field]: value }
        setBreakers(newBreakers)
    }

    const handleRemove = (index: number) => {
        setBreakers(breakers.filter((_, i) => i !== index))
    }

    const handleSave = async () => {
        if (!userId) return

        // Validation
        if (breakers.some(b => !b.question?.trim() || !b.response?.trim())) {
            toast.error("Please fill in all fields")
            return
        }

        setSaving(true)
        try {
            const res = await fetch("/api/ice-breakers", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ userId, iceBreakers: breakers })
            })

            let data: any = null
            try {
                data = await res.json()
            } catch {
                data = null
            }

            if (!data || typeof data !== "object" || Array.isArray(data)) {
                toast.warning("Save result could not be confirmed. Please do not retry immediately.")
                await refreshBreakers()
                return
            }

            if (data.partialSuccess || data.operationUncertain) {
                toast.warning(
                    data.warning || "The save result could not be fully confirmed. Please do not retry immediately."
                )
                await refreshBreakers()
            } else if (data.success && data.warning) {
                toast.warning(data.warning)
                await refreshBreakers()
            } else if (data.success) {
                toast.success("Ice Breakers saved & synced successfully!")
                await refreshBreakers()
            } else {
                toast.error(data.error || "Failed to save Ice Breakers. Please try again.")
            }
        } catch {
            console.error("[IceBreakers] Save error: category=NETWORK_ERROR")
            toast.warning("Save result could not be confirmed due to a network error. Please do not retry immediately.")
            await refreshBreakers()
        } finally {
            setSaving(false)
        }
    }

    if (isLoading) {
        return (
            <div className="p-10 flex justify-center">
                <Loader2 className="animate-spin text-accent-yellow-foreground dark:text-accent-yellow" />
            </div>
        )
    }

    if (!userId) {
        return (
            <div className="space-y-6 max-w-2xl mx-auto">
                <div className="text-center py-10 border border-border rounded-xl text-muted-foreground bg-card">
                    <p className="text-sm font-medium">Not connected</p>
                    <p className="text-xs mt-1">Connect your Instagram account to manage Ice Breakers.</p>
                </div>
            </div>
        )
    }

    if (fetching && !breakers.length) {
        return (
            <div className="p-10 flex justify-center">
                <Loader2 className="animate-spin text-accent-yellow-foreground dark:text-accent-yellow" />
            </div>
        )
    }

    return (
        <div className="space-y-6 max-w-4xl mx-auto">
            <div className="flex items-center justify-between">
                <div>
                    <h2 className="text-3xl font-semibold tracking-[-0.03em] text-foreground">Conversation starters</h2>
                    <p className="text-muted-foreground text-sm">
                        Questions people see when they start a chat with you.
                    </p>
                </div>
                <Button
                    onClick={handleSave}
                    disabled={saving}
                    className="bg-primary text-primary-foreground hover:opacity-90 font-bold"
                >
                    {saving ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : <Save className="w-4 h-4 mr-2" />}
                    Save & Sync
                </Button>
            </div>

            <div className="space-y-4">
                {breakers.map((item, idx) => (
                    <div key={idx} className="bg-card border border-border p-4 rounded-xl space-y-3 relative group">
                        <div className="flex justify-between items-start gap-4">
                            <div className="flex-1 space-y-3">
                                <div>
                                    <label className="text-xs text-muted-foreground font-semibold uppercase">Question</label>
                                    <Input
                                        value={item.question}
                                        onChange={e => handleChange(idx, "question", e.target.value)}
                                        placeholder="e.g., What are your prices?"
                                        className="bg-background border-input mt-1 focus-visible:ring-ring"
                                        maxLength={80}
                                    />
                                </div>
                                <div>
                                    <label className="text-xs text-muted-foreground font-semibold uppercase">Auto-Response</label>
                                    <Textarea
                                        value={item.response}
                                        onChange={e => handleChange(idx, "response", e.target.value)}
                                        placeholder="The reply users will receive..."
                                        className="bg-background border-input mt-1 focus-visible:ring-ring"
                                        rows={2}
                                    />
                                </div>
                            </div>
                            <Button
                                variant="ghost"
                                size="icon"
                                onClick={() => handleRemove(idx)}
                                aria-label="Remove ice breaker"
                                className="text-muted-foreground hover:text-destructive hover:bg-destructive/10"
                            >
                                <Trash2 className="w-4 h-4" />
                            </Button>
                        </div>
                    </div>
                ))}

                {breakers.length === 0 && (
                    <div className="text-center py-10 border border-border rounded-xl text-muted-foreground bg-card">
                        No ice breakers yet. Add one to get started!
                    </div>
                )}

                {breakers.length < 4 && (
                    <Button
                        variant="outline"
                        onClick={handleAdd}
                        className="w-full border-border bg-card hover:bg-accent text-muted-foreground hover:text-foreground"
                    >
                        <Plus className="w-4 h-4 mr-2" /> Add Question
                    </Button>
                )}
            </div>

            <div className="bg-muted border border-border p-4 rounded-xl flex gap-3 text-sm text-foreground">
                <RefreshCw className="w-5 h-5 shrink-0 text-muted-foreground" />
                <p>
                    Saving changes updates your database and attempts to sync your Instagram profile. Sync failures are reported separately.
                </p>
            </div>
        </div>
    )
}
