"use client"

import type React from "react"

import { useEffect, useState } from "react"
import { useRouter } from "next/navigation"
import { zodResolver } from "@hookform/resolvers/zod"
import { useForm } from "react-hook-form"
import { z } from "zod"
import { Filter, Search } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Form, FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form"
import { Input } from "@/components/ui/input"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"
import { useToast } from "@/components/ui/use-toast"
import { ProjectList } from "@/components/project-list"
import { DashboardHeader } from "@/components/dashboard-header"
import { getUserInfo, isAuthenticated } from "@/lib/auth"
import { addProject } from "@/lib/api"

const projectSchema = z.object({
  title: z.string().min(2, {
    message: "Title must be at least 2 characters.",
  }),
  hostedLink: z.string().url({
    message: "Please enter a valid URL.",
  }),
  githubLink: z.string().url({
    message: "Please enter a valid GitHub URL.",
  }),
  description: z.string().min(10, {
    message: "Description must be at least 10 characters.",
  }),
  githubUsername: z.string().min(1, {
    message: "GitHub username is required.",
  }),
})

export default function DashboardPage() {
  const router = useRouter()
  const { toast } = useToast()
  const [isLoading, setIsLoading] = useState(false)
  const [isClient, setIsClient] = useState(false)
  const [screenshot, setScreenshot] = useState<File | null>(null)
  const [authError, setAuthError] = useState<string | null>(null)
  const [searchTerm, setSearchTerm] = useState("")
  const [showOnlyMyProjects, setShowOnlyMyProjects] = useState(false)
  const [currentUsername, setCurrentUsername] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState("projects")

  // Check if user is authenticated
  useEffect(() => {
    const checkAuth = async () => {
      try {
        setIsClient(true)
  
        if (!isAuthenticated()) {
          console.log("Not authenticated, redirecting to login")
          router.push("/login")
          return
        }
  
        // Get current user info for filtering
        const userInfo = await getUserInfo()
        if (userInfo) {
          setCurrentUsername(userInfo.name)
  
          // Pre-fill the GitHub username in the form
          form.setValue("githubUsername", userInfo.name || '')
        }
      } catch (error) {
        console.error("Authentication error:", error)
        setAuthError("Authentication error. Please try logging in again.")
      }
    }

    checkAuth()
  }, [router])

  const form = useForm<z.infer<typeof projectSchema>>({
    resolver: zodResolver(projectSchema),
    defaultValues: {
      title: "",
      hostedLink: "",
      githubLink: "",
      description: "",
      githubUsername: "",
    },
  })

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setScreenshot(e.target.files[0])
    }
  }

  const handleSearch = (e: React.ChangeEvent<HTMLInputElement>) => {
    setSearchTerm(e.target.value)
  }

  const toggleMyProjects = () => {
    setShowOnlyMyProjects(!showOnlyMyProjects)
  }

  const handleTabChange = (value: string) => {
    setActiveTab(value)
  }

  async function onSubmit(values: z.infer<typeof projectSchema>) {
    if (!screenshot) {
      toast({
        title: "Error",
        description: "Please upload a screenshot of your project.",
        variant: "destructive",
      })
      return
    }

    setIsLoading(true)

    try {
      // Create a FormData object to send the file
      const formData = new FormData()
      formData.append("screenshot", screenshot)
      formData.append("title", values.title)
      formData.append("hostedLink", values.hostedLink)
      formData.append("githubLink", values.githubLink)
      formData.append("description", values.description)
      formData.append("githubUsername", values.githubUsername)

      // For development/testing purposes
      if (process.env.NODE_ENV === "development") {
        // Simulate successful project addition
        setTimeout(() => {
          toast({
            title: "Project added!",
            description: "Your project has been successfully added.",
          })

          // Reset the form
          form.reset()
          setScreenshot(null)

          // Switch to the projects tab
          setActiveTab("projects")

          setIsLoading(false)
        }, 1000)
      } else {
        // Production project addition with real API
        await addProject(formData)

        toast({
          title: "Project added!",
          description: "Your project has been successfully added.",
        })

        // Reset the form
        form.reset()
        setScreenshot(null)

        // Switch to the projects tab
        setActiveTab("projects")
      }
    } catch (error) {
      console.error("Error adding project:", error)
      toast({
        title: "Error",
        description: error instanceof Error ? error.message : "Something went wrong. Please try again.",
        variant: "destructive",
      })
    } finally {
      setIsLoading(false)
    }
  }

  if (!isClient) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto"></div>
          <p className="mt-4 text-lg">Loading...</p>
        </div>
      </div>
    )
  }

  if (authError) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Card className="w-full max-w-md">
          <CardHeader>
            <CardTitle className="text-xl text-destructive">Authentication Error</CardTitle>
          </CardHeader>
          <CardContent>
            <p>{authError}</p>
            <Button
              className="w-full mt-4"
              onClick={() => {
                localStorage.removeItem("token")
                router.push("/login")
              }}
            >
              Back to Login
            </Button>
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="flex min-h-screen flex-col">
      <DashboardHeader />
      <main className="flex-1 container py-8">
        <Tabs value={activeTab} onValueChange={handleTabChange} className="space-y-6">
          <TabsList>
            <TabsTrigger value="projects">My Projects</TabsTrigger>
            <TabsTrigger value="add">Add Project</TabsTrigger>
          </TabsList>

          <TabsContent value="projects" className="space-y-6">
            <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
              <h2 className="text-2xl font-bold tracking-tight">Projects</h2>
              <div className="flex items-center gap-2">
                <div className="relative w-full sm:w-64">
                  <Search className="absolute left-2 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                  <Input
                    placeholder="Search projects..."
                    value={searchTerm}
                    onChange={handleSearch}
                    className="w-full pl-8"
                  />
                </div>
                <Button
                  variant={showOnlyMyProjects ? "default" : "outline"}
                  size="sm"
                  onClick={toggleMyProjects}
                  className="gap-2"
                >
                  <Filter className="h-4 w-4" />
                  {showOnlyMyProjects ? "My Projects" : "All Projects"}
                </Button>
              </div>
            </div>
            <ProjectList
              searchTerm={searchTerm}
              filterByUser={showOnlyMyProjects}
              onProjectsChange={() => {
                // Refresh the list when projects change
                setSearchTerm("")
              }}
            />
          </TabsContent>

          <TabsContent value="add">
            <Card>
              <CardHeader>
                <CardTitle>Add New Project</CardTitle>
                <CardDescription>Showcase your work by adding a new project to your portfolio.</CardDescription>
              </CardHeader>
              <CardContent>
                <Form {...form}>
                  <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
                    <FormField
                      control={form.control}
                      name="title"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Project Title</FormLabel>
                          <FormControl>
                            <Input placeholder="My Awesome Project" {...field} />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />

                    <FormItem>
                      <FormLabel>Screenshot</FormLabel>
                      <FormControl>
                        <Input type="file" accept="image/*" onChange={handleFileChange} />
                      </FormControl>
                      <FormDescription>Upload a screenshot of your project (PNG, JPG, or WEBP)</FormDescription>
                      <FormMessage />
                    </FormItem>

                    <FormField
                      control={form.control}
                      name="hostedLink"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Hosted Link</FormLabel>
                          <FormControl>
                            <Input placeholder="https://myproject.com" {...field} />
                          </FormControl>
                          <FormDescription>Link to the live version of your project</FormDescription>
                          <FormMessage />
                        </FormItem>
                      )}
                    />

                    <FormField
                      control={form.control}
                      name="githubLink"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>GitHub Link</FormLabel>
                          <FormControl>
                            <Input placeholder="https://github.com/username/repo" {...field} />
                          </FormControl>
                          <FormDescription>Link to your project's GitHub repository</FormDescription>
                          <FormMessage />
                        </FormItem>
                      )}
                    />

                    <FormField
                      control={form.control}
                      name="githubUsername"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>GitHub Username</FormLabel>
                          <FormControl>
                            <Input placeholder="username" {...field} />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />

                    <FormField
                      control={form.control}
                      name="description"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Description</FormLabel>
                          <FormControl>
                            <Textarea
                              placeholder="Describe your project, technologies used, and any other relevant information."
                              className="min-h-[120px]"
                              {...field}
                            />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />

                    <Button type="submit" className="w-full" disabled={isLoading}>
                      {isLoading ? "Adding Project..." : "Add Project"}
                    </Button>
                  </form>
                </Form>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </main>
    </div>
  )
}

